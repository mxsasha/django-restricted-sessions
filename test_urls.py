from django.conf.urls import url
try:
    from django.conf.urls import patterns
except ImportError:
    patterns = lambda x**: list(x)
from django.http import HttpResponse


urlpatterns = patterns(
    '',
    url(
        regex=r'test_view/',
        view=lambda r: HttpResponse(content="For unittests", status=200),
        name='test_view'
    ),
)
