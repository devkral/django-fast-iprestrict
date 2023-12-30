from django.contrib.auth.models import User
from django.test import TestCase

admin_index_pages = [
    "/admin/django_fast_iprestrict/",
    "/admin/django_fast_iprestrict/rulenetwork",
    "/admin/django_fast_iprestrict/rulepath",
    "/admin/django_fast_iprestrict/rulesource",
    "/admin/django_fast_iprestrict/rule",
]


class SyncTests(TestCase):
    def setUp(self):
        self.admin_user = User.objects.create_superuser(name="admin")

    def test_admin(self):
        self.client.force_login(self.admin_user)
        for page in admin_index_pages:
            response = self.client.get(page)
            self.assertEqual(response.status, 200)


class AsyncTests(TestCase):
    pass
