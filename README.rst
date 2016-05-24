=============================
django-restricted-sessions
=============================

.. image:: https://badge.fury.io/py/django-restricted-sessions.png
    :target: http://badge.fury.io/py/django-restricted-sessions

.. image:: https://travis-ci.org/erikr/django-restricted-sessions.png?branch=master
    :target: https://travis-ci.org/erikr/django-restricted-sessions

.. image:: https://coveralls.io/repos/erikr/django-restricted-sessions/badge.png?branch=master&
    :target: https://coveralls.io/r/erikr/django-restricted-sessions?branch=master

Restricts Django sessions to IP and/or user agent.

If the IP or user agent changes after creating the session, the a 400 response is given to the request, the session is
flushed (all session data deleted, new session created) and a warning is logged. The goal of this middleware is to
make it harder for an attacker to use a session ID they obtained. It does not make abuse of session IDs impossible.

For compatibility with IPv6 privacy extensions, by default only the first 64 bits of an IPv6 address are checked.

Documentation
-------------

The full documentation is at https://django-restricted-sessions.readthedocs.org.

Quickstart
----------

Install django-restricted-sessions::

    pip install django-restricted-sessions

Then add it to your middleware after SessionMiddleware::

    MIDDLEWARE_CLASSES = [
        ....
        'django.contrib.sessions.middleware.SessionMiddleware',
        # 'django.contrib.auth.middleware.AuthenticationMiddleware',
        'restrictedsessions.middleware.RestrictedSessionsMiddleware',
        ....
    ]

When ``RESTRICTEDSESSIONS_AUTHED_ONLY`` setting enabled ensure this middleware is added after
``AuthenticationMiddleware`` such that the ``request.user`` is present.
