import sys

import django
from django.core.management import call_command

try:
    from django.conf import settings

    settings.configure(
        DEBUG=True,
        USE_TZ=True,
        SECRET_KEY='VERY_SECRET',
        DATABASES={
            "default": {
                "NAME": "./test.sqlite",
                "ENGINE": "django.db.backends.sqlite3",
            }
        },
        ROOT_URLCONF="test_urls",
        INSTALLED_APPS=[
            "django.contrib.auth",
            "django.contrib.contenttypes",
            "django.contrib.sites",
            "django.contrib.sessions",
            "restrictedsessions",
        ],
        MIDDLEWARE=[
            'django.contrib.sessions.middleware.SessionMiddleware',
            'restrictedsessions.middleware.RestrictedSessionsMiddleware',
            'django.middleware.common.CommonMiddleware',
            'django.middleware.csrf.CsrfViewMiddleware',
            'django.contrib.auth.middleware.AuthenticationMiddleware',
            'django.contrib.messages.middleware.MessageMiddleware',
            'django.middleware.clickjacking.XFrameOptionsMiddleware',
        ],
        SITE_ID=1,
    )
    django.setup()

except ImportError:
    raise ImportError("To fix this error, run: pip install -r requirements-test.txt")


def run_tests(*test_args):
    # Run tests
    call_command('test', test_args)


if __name__ == '__main__':
    run_tests(*sys.argv[1:])
