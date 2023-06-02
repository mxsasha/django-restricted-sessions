from django.urls import re_path
from django.http import HttpResponse


urlpatterns = [
    re_path(
        r'test_view/',
        view=lambda r: HttpResponse(content="For unittests", status=200),
        name='test_view'
    ),
]
