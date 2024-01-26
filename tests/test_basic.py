import time
from unittest.mock import patch

import django_fast_ratelimit as ratelimit
from django.contrib.auth.models import User
from django.test import RequestFactory, TestCase, override_settings

from django_fast_iprestrict.models import RATELIMIT_ACTION, Rule, RuleSource
from django_fast_iprestrict.utils import RULE_ACTION, LockoutException

admin_index_pages = [
    "/admin/django_fast_iprestrict/",
    "/admin/django_fast_iprestrict/rulenetwork/",
    "/admin/django_fast_iprestrict/rulepath/",
    "/admin/django_fast_iprestrict/rulesource/",
    "/admin/django_fast_iprestrict/rule/",
]


def test_iprestrict_gen():
    return ["::2", "127.0.0.2"]


def test_iprestrict_2gen():
    raise


def test_notallowed_iprestrict_gen():
    return ["::2", "127.0.0.2"]


class SyncTests(TestCase):
    def setUp(self):
        self.admin_user = User.objects.create_superuser(username="admin")

    def test_admin_default(self):
        self.client.force_login(self.admin_user)
        for page in admin_index_pages:
            with self.subTest("plain (without rules) for page: %(page)s", page=page):
                response = self.client.get(page)
                self.assertEqual(response.status_code, 200)
        rule = Rule.objects.create(name="test", action=RULE_ACTION.disabled)
        self.assertFalse(rule.is_catch_all())
        self.assertTrue(rule.is_catch_all(also_disabled=True))
        for page in admin_index_pages:
            with self.subTest(
                "plain (with disabled rules) for page: %(page)s", page=page
            ):
                response = self.client.get(page)
                self.assertEqual(response.status_code, 200)
        rule.action = RULE_ACTION.deny.value
        rule.save()
        with self.assertRaises(LockoutException):
            Rule.objects.lockout_check(ip="127.0.0.1")
        Rule.objects.lockout_check(ip="127.0.0.1", path="/foobar/")
        rule.pathes.create(path="/foobar/")
        Rule.objects.lockout_check(ip="127.0.0.1")
        with self.assertRaises(LockoutException):
            Rule.objects.lockout_check(ip="127.0.0.1", path="/foobar/")
        rule_allow_all = Rule.objects.create(name="allow_all", action=RULE_ACTION.allow)
        rule_allow_all.pathes.create(path=".*", is_regex=True)
        Rule.objects.lockout_check(ip="127.0.0.1")
        with self.assertRaises(LockoutException):
            Rule.objects.lockout_check(ip="127.0.0.1", path="/foobar/")
        with self.subTest("moving position"):
            # includes lockout check
            Rule.objects.position_up(rule_allow_all.id, ip="127.0.0.1", path="/foobar/")
            # reverts to original state
            with self.assertRaises(LockoutException):
                Rule.objects.position_down(
                    rule_allow_all.id, ip="127.0.0.1", path="/foobar/"
                )
            # skip lockout check
            Rule.objects.position_start(rule.id)
            with self.assertRaises(LockoutException):
                Rule.objects.lockout_check(ip="127.0.0.1", path="/foobar/")
            Rule.objects.position_end(rule.id, ip="127.0.0.1", path="/foobar/")
        with self.subTest("check admin after adding rules"):
            for page in admin_index_pages:
                response = self.client.get(page)
                self.assertEqual(response.status_code, 200)

    @patch("tests.test_basic.test_iprestrict_gen", side_effect=test_iprestrict_gen)
    def test_sources(self, generator):
        rule = Rule.objects.create(name="test", action=RULE_ACTION.deny)
        rule.sources.create(
            generator_fn="tests.test_basic.test_iprestrict_gen", interval=3
        )
        RuleSource.objects.clear_remote_caches()
        self.assertEqual(generator.call_count, 0)
        self.assertEqual(
            rule.match_ip(ip="127.0.0.2", remote=False)[1],
            RULE_ACTION.allow,
        )
        self.assertEqual(generator.call_count, 0)
        self.assertEqual(rule.match_ip(ip="127.0.0.1")[1], RULE_ACTION.allow)
        self.assertEqual(generator.call_count, 1)
        self.assertEqual(rule.match_ip(ip="127.0.0.2")[1], RULE_ACTION.deny)
        self.assertEqual(generator.call_count, 1)
        self.assertEqual(rule.match_ip(ip="::2")[1], RULE_ACTION.deny)
        self.assertEqual(generator.call_count, 1)
        time.sleep(3)
        self.assertEqual(rule.match_ip(ip="::2")[1], RULE_ACTION.deny)
        self.assertEqual(generator.call_count, 2)

    test_sources_no_force_expire = override_settings(
        IPRESTRICT_SOURCE_FORCE_EXPIRE=False
    )(test_sources)

    @patch("tests.test_basic.test_iprestrict_gen", side_effect=test_iprestrict_gen)
    def test_sources2(self, generator):
        rule = Rule.objects.create(name="test", action=RULE_ACTION.deny)
        rule.sources.create(
            generator_fn="tests.test_basic.test_iprestrict_gen", interval=0
        )
        RuleSource.objects.clear_remote_caches()
        self.assertEqual(generator.call_count, 0)
        self.assertEqual(
            rule.match_ip(ip="127.0.0.2", remote=False)[1],
            RULE_ACTION.allow,
        )
        self.assertEqual(generator.call_count, 0)
        self.assertEqual(rule.match_ip(ip="127.0.0.1")[1], RULE_ACTION.allow)
        self.assertEqual(generator.call_count, 1)
        self.assertEqual(rule.match_ip(ip="127.0.0.2")[1], RULE_ACTION.deny)
        self.assertEqual(generator.call_count, 2)
        self.assertEqual(rule.match_ip(ip="::2")[1], RULE_ACTION.deny)
        self.assertEqual(generator.call_count, 3)

    test_sources2_no_force_expire = override_settings(
        IPRESTRICT_SOURCE_FORCE_EXPIRE=False
    )(test_sources2)

    def test_invalid_sources(self):
        rule = Rule.objects.create(name="test", action=RULE_ACTION.deny)
        rule.sources.create(generator_fn="tests.test_basic.non_existing", interval=0)
        rule.sources.create(
            generator_fn="tests.test_basic.test_iprestrict_2gen", interval=0
        )
        rule.sources.create(
            generator_fn="tests.test_basic.test_notallowed_iprestrict_gen", interval=0
        )
        RuleSource.objects.clear_remote_caches()
        with self.assertLogs():
            RuleSource.objects.ip_matchers_remote([rule])

    def test_as_ratelimit_fn_two_phased(self):
        @ratelimit.decorate(
            key="django_fast_iprestrict.apply_iprestrict:execute_only",
            group="test",
        )
        def fn(request):
            return "foo"

        factory = RequestFactory()
        rule = Rule.objects.create(
            name="arbitary_name", action=RULE_ACTION.only_ratelimit
        )
        rule.ratelimit_groups.create(name="test")
        rule.ratelimits.create(
            key="static",
            rate="1/2m",
            group="test_as_ratelimit_fn_two_phased",
            block=True,
            is_active=True,
            action=RATELIMIT_ACTION.INCREASE,
        )
        for i in range(3):
            request = factory.get("/foobar/")
            fn(request)
        for i in range(3):
            request = factory.get("/foobar/")
            ratelimit.get_ratelimit(
                request=request,
                key="django_fast_iprestrict.apply_iprestrict:count_only",
                group="test",
            )
        with self.assertRaises(ratelimit.RatelimitExceeded):
            request = factory.get("/foobar/")
            fn(
                request,
            )

    def test_as_ratelimit_fn_plain(self):
        rule_unrelated = Rule.objects.create(name="unrelated", action=RULE_ACTION.deny)
        rule_unrelated.pathes.create(path=".*", is_regex=True)
        factory = RequestFactory()
        rule = Rule.objects.create(name="arbitary_name", action=RULE_ACTION.deny)
        rule.ratelimit_groups.create(name="test")
        request = factory.get("/foobar/")
        r = ratelimit.get_ratelimit(
            request=request,
            key="django_fast_iprestrict.apply_iprestrict",
            group="test",
        )
        self.assertGreaterEqual(r.request_limit, 1)
        rule.action = RULE_ACTION.allow.value
        rule.save()
        request = factory.get("/foobar/")
        r = ratelimit.get_ratelimit(
            request=request,
            key="django_fast_iprestrict.apply_iprestrict",
            group="test",
        )
        self.assertGreaterEqual(r.request_limit, 0)
        request = factory.get("/foobar/")
        r = ratelimit.get_ratelimit(
            request=request,
            key="django_fast_iprestrict.apply_iprestrict:require_rule",
            group="test2",
        )
        self.assertGreaterEqual(r.request_limit, 1)

    def test_as_ratelimit_fn_pathes(self):
        rule_unrelated = Rule.objects.create(name="unrelated", action=RULE_ACTION.deny)
        rule_unrelated.pathes.create(path=".*", is_regex=True)
        factory = RequestFactory()
        rule = Rule.objects.create(name="arbitary_name", action=RULE_ACTION.deny)
        rule.ratelimit_groups.create(name="test")
        rule.pathes.create(path="/foobar/")
        request = factory.get("/foobar/")
        r = ratelimit.get_ratelimit(
            request=request,
            key="django_fast_iprestrict.apply_iprestrict",
            group="test",
        )
        self.assertGreaterEqual(r.request_limit, 1)
        request = factory.get("/foobar2/")
        r = ratelimit.get_ratelimit(
            request=request,
            key="django_fast_iprestrict.apply_iprestrict",
            group="test",
        )
        self.assertEqual(r.request_limit, 0)
        request = factory.get("/foobar2/")
        r = ratelimit.get_ratelimit(
            request=request,
            key="django_fast_iprestrict.apply_iprestrict:ignore_pathes",
            group="test",
        )
        self.assertEqual(r.request_limit, 0)  # is not a catch all because of pathes
        rule.networks.create(network="0.0.0.0/0")
        rule.networks.create(network="::/0")
        request = factory.get("/foobar2/")
        r = ratelimit.get_ratelimit(
            request=request,
            key="django_fast_iprestrict.apply_iprestrict:ignore_pathes",
            group="test",
        )
        self.assertEqual(r.request_limit, 1)
        request = factory.get("/foobar/")
        r = ratelimit.get_ratelimit(
            request=request,
            key="django_fast_iprestrict.apply_iprestrict:require_rule,ignore_pathes",
            group="test2",
        )
        self.assertGreaterEqual(r.request_limit, 1)

    def test_ratelimit_middleware(self):
        self.client.force_login(self.admin_user)
        rule = Rule.objects.create(
            name="test",
            action=RULE_ACTION.only_ratelimit,
            invert_methods=True,
            methods="",
        )
        rule.pathes.create(path=".*", is_regex=True)
        rule.ratelimits.create(
            key="user",
            rate="1/2m",
            group="test_ratelimit_middleware",
            block=True,
            is_active=True,
        )
        response = self.client.get(admin_index_pages[0])
        self.assertEqual(response.status_code, 200)
        self.assertTrue(hasattr(response.wsgi_request, "ratelimit"))
        response = self.client.get(admin_index_pages[0])
        self.assertTrue(hasattr(response.wsgi_request, "ratelimit"))
        self.assertEqual(response.status_code, 403)


class AsyncTests(TestCase):
    pass
