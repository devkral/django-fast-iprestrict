# django-fast-iprestrict

Django-fast-iprestrict provides a secure facility based on the django admin framework to restrict the access for the whole project or
for parts of it to special ips or denylisting some ip networks.
Internal only networks are used for ip matching and for path matching regex is used (Note: when regex is turned of (default) the pathmatcher just escapes the strings before feeding them to the regex pattern)

The name comes from the relationship to django-fast-ratelimit.

It is even possible to use django-fast-iprestrict in django-fast-ratelimit

## Installation

```sh
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

Note: pip >= 19 is required

## usage

In the admin panel is now a section Rule and Rule Pathes. Rule pathes like `.*` can be used to match for the whole project.

Rules are evalutated like a waterfall:
the lowest position to the highest position. State disabled rules are skipped

Note: ipv4 and ipv6 rules are not interoperable yet. If the network does not match they are skipped like if they are in state "disabled".

The rule names can be used for the django-fast-ratelimit adapter:

```python

import ratelimit

r = ratelimit.get_ratelimit(key="django_fast_iprestrict.apply_iprestrict", groups="rulename", rate="1/1s")

# or when only checking ips and not pathes (when pathes are available)

r = ratelimit.get_ratelimit(key="django_fast_iprestrict.apply_iprestrict:ignore_pathes", groups="rulename", rate="1/1s")

# or as decorator
@ratelimit(key="django_fast_iprestrict.apply_iprestrict", groups="rulename", rate="1/1s")
def foo(request):
    return ""

```

## settings

IPRESTRICT_CACHE: select cache, defaults to "default" cache
IPRESTRICT_KEY_PREFIX: cache key prefix, defaults to "fip:"
IPRESTRICT_DEFAULT_ACTION: "allow"/"deny" : default action when no rule matches, default, when unset is "allow". "allow" or unset is strongly recommended except you want to set the rules programmatically
IPRESTRICT_TRUSTED_PROXIES: set list of trusted proxies
RATELIMIT_TRUSTED_PROXIES: fallback when IPRESTRICT_TRUSTED_PROXIES is unset
IPRESTRICT_TESTCLIENT_FALLBACK: fallback for the string testclient in the ip field. Dev setting for tests
RATELIMIT_TESTCLIENT_FALLBACK: fallback when IPRESTRICT_TESTCLIENT_FALLBACK is unset

The ratelimit settings are fallbacks, so the settings must only be set on one place

## development

a development environment can be setup this way (poetry is recommended):

```sh
# installation then
poetry run ./manage.py createsuperuser
poetry run ./manage.py runserver

```

Note:

given the lack of tests and the early development state, it is possible that some parts have erratas.

# GEOIP

GEOIP can be done via sources (WIP)

# TODO

-   localization?
-   remote fetch sources and cache them. Use get_many set_many to retrieve them
-   docs for new settings
