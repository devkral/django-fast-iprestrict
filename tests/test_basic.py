from django.contrib.auth.models import User
from django.test import TestCase

from django_fast_iprestrict.models import Rule
from django_fast_iprestrict.utils import RULE_ACTION, LockoutException

admin_index_pages = [
    "/admin/django_fast_iprestrict/",
    "/admin/django_fast_iprestrict/rulenetwork/",
    "/admin/django_fast_iprestrict/rulepath/",
    "/admin/django_fast_iprestrict/rulesource/",
    "/admin/django_fast_iprestrict/rule/",
]


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


class AsyncTests(TestCase):
    pass
