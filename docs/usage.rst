=====
Usage
=====

Setup
-----

Add the ``RestrictedSessionsMiddleware`` to your ``MIDDLEWARE`` setting, after ``SessionMiddleware``::

    MIDDLEWARE = [
        "django.middleware.security.SecurityMiddleware",
        "django.contrib.sessions.middleware.SessionMiddleware",
        'restrictedsessions.middleware.RestrictedSessionsMiddleware',
        ....
    ]

When ``RestrictedSessionsMiddleware`` sees a request with a new session, it will store the client's current IP and
user agent in the session. Upon further requests, it will validate the IP and user agent. If changes have occured,
a 400 response is returned, the session is flushed and a warning is logged.

By default, for IPv4 addresses, the address must remain exactly the same. For IPv6 address, the first 64 bits must
remain the same. The latter 64 bits may change rapidly in clients that have IPv6 privacy extensions (RFC4941) enabled,
so rigorous checks on those will only annoy users. User agents must also remain exactly the same.

When encountering requests without a session, or in which the client IP could not be found, the middleware takes
no action.


Settings
--------

The following settings are available:

 * ``RESTRICTEDSESSIONS_RESTRICT_IP`` (bool, default: True): restrict sessions based on IP address.
 * ``RESTRICTEDSESSIONS_RESTRICT_UA`` (bool, default: True): restrict sessions based on user agent.
 * ``RESTRICTEDSESSIONS_REMOTE_ADDR_KEY`` (string, default: 'REMOTE_ADDR'): key in request.META under which the real
   IP address can be found. This may differ depending on the setup of the web and WSGI server.
 * ``RESTRICTEDSESSIONS_IPV4_LENGTH`` (int, default: 32): number of bits to consider when comparing IPv4 addresses. 32
   means the full address must be equal, 24 would mean that a change from 192.0.2.1 to 192.0.2.200 is allowed, but not
   to 192.0.3.1.
 * ``RESTRICTEDSESSIONS_IPV6_LENGTH`` (int, default: 64): number of bits to consider when comparing IPv6 addresses.
   128 means the full address must be equal. 64 means that a change from 2001:db8::1 to 2001:db8::3 is allowed, but not
   to 2001:db9::1. Setting this to 128 is not recommended, as it will cause frequent session invalidation if clients
   use IPv6 privacy extensions.
 * ``RESTRICTEDSESSIONS_REDIRECT_VIEW`` (string, default: None): when this value is set to be a known view
   configured within the project's ROOT_URLCONF, then any failure of the session validation will redirect to this
   location after the session is cleared/flushed.
 * ``RESTRICTEDSESSIONS_FAILURE_STATUS`` (int, default: 400) the HTTP status code to return when
   not utilizing RESTRICTEDSESSIONS_REDIRECT_VIEW setting such that any failure of the session validation
   will return this status code.
 * ``RESTRICTEDSESSIONS_AUTHED_ONLY`` (bool, default: False) when set to true, only restricts the sessions
   for authenticated users.  Utilizes the `django.contrib.auth.logout` method to invalidate the session when enabled.


How much added security does this offer?
----------------------------------------

In a case where an attacker is able to obtain a session ID and tries to reuse it, this middleware will prevent this
if the attacker is not careful. Once an attacker has the session ID, it is fairly likely that they also know
the original user agent, which they could spoof. If they are in the same location as the victim, they may also be
using the same IPv4 address or IPv6 block. Therefore, this middleware adds an extra hurdle for session ID abuse at
very low cost, but will not help against careful attackers in the right situations.
