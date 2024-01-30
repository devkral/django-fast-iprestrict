# django-fast-iprestrict

Django-fast-iprestrict provides a secure facility based on the django admin framework to restrict the access for the whole project or
for parts of it to special ips or denylisting some ip networks.
Internal only networks are used for ip matching and for path matching regex is used (Note: when regex is turned of (default) the pathmatcher just escapes the strings before feeding them to the regex pattern)

The name comes from the relationship to django-fast-ratelimit.

It is even possible to use django-fast-iprestrict in django-fast-ratelimit

## Installation

```sh
pip install django-fast-iprestrict[ratelimit]

# or the limited without ratelimit integration

pip install django-fast-iprestrict

```

Now add to python settings

settings:

```python


INSTALLED_APPS = [
    ...
    "django_fast_iprestrict",
]

# if wanted (it is also possible to use this tool only with django-fast-ratelimit)

MIDDLEWARE = [
    ...
    "django_fast_iprestrict.middleware.fast_iprestrict",
    ...
]
```

## usage

### admin panel

In the admin panel is now a section Ip Restrict.
It contains multiple subsections from which only Rule allows to create new objects.
The other subsections are only an overview.

All of these subsections contain a test utility for checking arbitary pathes and ips

Rule pathes like `.*` can be used to match for the whole project.

Rules are evalutated like a waterfall:
the lowest position to the highest position. State disabled rules are skipped

Note: ipv4 and ipv6 rules are not interoperable. If the network does not match they are skipped like if they are in state "disabled".


#### ratelimits

ratelimits can be specified or a rule can be made to a ratelimit matcher (called programmatically via django-fast-ratelimit)

In the last case it is possible to provide the rate "inherit" for using the rate specified in the django-fast-ratelimit call.

If no rate was passed, ratelimits with rate "inherit" will be ignored

### programmatically

The rule names can be used for the django-fast-ratelimit adapter if RuleRatelimitGroups are defined and active. When some are defined the rule isn't used anymore in normal matching but only in apply_iprestrict.

Note: deactivated RuleRatelimitGroups still prevent the normal mode, the RuleRatelimitGroups have to be deleted to revert to the normal matching

```python

import django_fast_ratelimit as ratelimit

r = ratelimit.get_ratelimit(key="django_fast_iprestrict.apply_iprestrict", groups="groupname")

# since django-fast-ratelimit 7.3, rate is not required anymore for older versions add stub rate
# Note: stub rates like 0/s will still raise Disabled
# Note: 1/s is used as the default rate for django-fast-ratelimit 8.0.0. This way rates can be passed to iprestrict
r = ratelimit.get_ratelimit(key="django_fast_iprestrict.apply_iprestrict", groups="groupname", rate="1/s")

# or when only checking ips and not pathes (when pathes are available)

r = ratelimit.get_ratelimit(key="django_fast_iprestrict.apply_iprestrict:ignore_pathes", groups="groupname")

# or when only checking ips and not pathes (when pathes are available) and requiring rule
r = ratelimit.get_ratelimit(key="django_fast_iprestrict.apply_iprestrict:ignore_pathes,require_rule", groups="groupname")

# tuple/array syntax
r = ratelimit.get_ratelimit(key=["django_fast_iprestrict.apply_iprestrict", "ignore_pathes", "require_rule"], groups="groupname")


# or as decorator with rule requirement
@ratelimit.decorate(key="django_fast_iprestrict.apply_iprestrict:require_rule", groups="groupname")
def foo(request):
    return ""


```

The following arguments are valid:

-   `ignore_pathes`: match only via ip
-   `require_rule`: raise Disabled if rule with rulename not exist
-   `execute_only`: only decorate request, evaluate matching iprestrict rule action, wait and block, don't modify the ratelimit counter, for two-phased execution models
-   `count_only`: don't apply wait and block, when rule exists return only 0 (allowed), update the counter only and decorate request, for two-phased execution models

Note: when the request is already annotated with a ratelimit with the same decorate_name both instances are merged

Note: you can provide a rate and set the field rate in iprestrict ratelimit to "inherit" for using the provided rate, this works only when a rate is specified

#### two phased execution model

Especially with async code it can be handy to have two phases:

an execution phase in which only wait/block is executed and the counter not modified. Its place is before an expensive function.
The most common place is a decorator in urls. `execute_only` argument

a count phase in which the ratelimit counter in cache is modified. Its place is after/in an expensive function.
In case of invariants or if the calculated result should not be wasted, no actions are executed. `count_only` argument

views.py:

```python
import django_fast_ratelimit as ratelimit
from django.views import View
from django.http.import HttpResponse

class MyView(View):
    def get(self, request):
        # without count only
        ratelimit.get_ratelimit(key="django_fast_iprestrict.apply_iprestrict", groups="rulename", request=request)
        return HttpResponse(b"foo", status=200)
    def post(self, request):
        # expensive function
        ratelimit.get_ratelimit(key="django_fast_iprestrict.apply_iprestrict:count_only", groups="rulename", request=request)
        return HttpResponse(b"foo", status=200)


```

urls.py:

```python
import django_fast_ratelimit as ratelimit
from .views import MyView

urlpatterns = [
    path(
        "foo/",
        ratelimit.decorate(key="django_fast_iprestrict.apply_iprestrict:execute_only", groups="rulename")(MyView.as_view()),
    ),
]

```

#### really lowlevel (without ratelimit)

There are currently 3 matching methods of interest
````python
from django_fast_iprestrict.models import Rule, RulePath


Rule.objects.match_ip(ip="someip")
Rule.objects.match_all_ip(ip="someip")
RulePath.objects.match_ip_and_path(ip="someip", path="/foo")

````

Note: the matching methods have much more arguments. See in source for details

You might want to ignore the generic argument of match_ip and match_all_ip, it is dangerous as it ignores disabled rules
and can easily lead to lock outs


#### thirdparty integration (really deep lowlevel)

All of the models have managed_fields attribute. It is a list and only a list is valid. You can add field names you want to lockdown.
This cannot be overwritten by GUI. It is for the integration in thirdparty software, so nobody can do bad things or even delete.

Note: you should either call clean or ensure that all list entries are field names


### Sources (GEOIP)

For GEOIP or other stuff sources can be used.

Sources are functions with prefixes in IPRESTRICT_ALLOWED_FN_PREFIXES (can also be the whole function).

Restriction: "\_" prefixed functions are not allowed

They are referenced in admin with their path, e.g.:

`tests.test_basic.test_iprestrict_gen` (=also working example in dev environment with test_settings)


### Ratelimits

ratelimits require the companion library django-fast-ratelimit. And they work only with it! Otherwise crashes are preprogrammed

Ratelimit keys are either the default builtin functions or functions with prefixes in IPRESTRICT_ALLOWED_FN_PREFIXES

## behaviour

### ipv4 ipv6

mapped ipv4 addresses are extracted to plain ipv4 addresses.
Networks only match if their type is matching to the ip. Therefor IPv4 networks will be ignored when checking an IPv6 address

### catch alls

When a rule has neither an active network, source nor path it is treated as a catch all for match_ip. This means it resolves for every ip.

A such catch all is not used for path checks. When a path is added to the catch all the behaviour changes:

when the path matches and no network nor source is attached to the rule, it resolves without an ip check.

This allows a path catch all with a path like:
`.*` with is_regex set

## settings

IPRESTRICT_ALLOWED_FN_PREFIXES: defaults to [] (empty list)
IPRESTRICT_CACHE: select cache, defaults to "default" cache
IPRESTRICT_KEY_PREFIX: cache key prefix, defaults to "fip:"
IPRESTRICT_SOURCE_FORCE_EXPIRE: force expire sources via extra cache entry, for dangling caches; defaults to True
IPRESTRICT_DEFAULT_ACTION: "allow"/"deny" : default action when no rule matches, default, when unset is "allow". "allow" or unset is strongly recommended except you want to set the rules programmatically
IPRESTRICT_TRUSTED_PROXIES: set list of trusted proxies
RATELIMIT_TRUSTED_PROXIES: fallback when IPRESTRICT_TRUSTED_PROXIES is unset
IPRESTRICT_TESTCLIENT_FALLBACK: fallback for the string testclient in the ip field. Dev setting for tests
RATELIMIT_TESTCLIENT_FALLBACK: fallback when IPRESTRICT_TESTCLIENT_FALLBACK is unset

The ratelimit settings are fallbacks, so when set the settings is applied for django-fast-ratelimit and django-fast-iprestrict (handy shortcut).

Note: when using ratelimit the ratelimit settings are used for ratelimits, they can differ when not using the fallback

Note: when disabling the setting IPRESTRICT_SOURCE_FORCE_EXPIRE and using sources make sure you clear the cache at project restart. E.g. in Docker start file or restart the cache server too
Otherwise old entries sometimes doesn't expire and can cause stale sources (hard to detect)

## commands

iprestrict_clear_caches: clear caches in use by iprestrict and ratelimit, kills other entries in the cache too

iprestrict_unrestrict_all: disable all rules, clear caches in use by iprestrict and ratelimit, kills other entries in the cache too (should only be used in emergencies)

## development

a development environment can be setup this way (poetry is recommended):

```sh
# installation then
poetry run ./manage.py createsuperuser
poetry run ./manage.py runserver

```
# changes

-   0.13: add RuleRatelimitGroup for explicitly use Rules with ratelimit. No longer just match the rule name

# TODO

-   filter for ratelimit enabled rules and not ratelimit enable rules
-   localization?
