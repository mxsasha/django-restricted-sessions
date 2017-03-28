from django.conf.urls import url
from django.http import HttpResponse


urlpatterns = [
    url(
        regex=r'test_view/',
        view=lambda r: HttpResponse(content="For unittests", status=200),
        name='test_view'
    ),
]
