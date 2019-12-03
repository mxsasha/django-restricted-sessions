.. :changelog:

History
-------

0.3.0 (2019-12-03)
++++++++++++++++++

* Updated Django support to 1.11, 2.2 and 3.0.
* Fixed issues when ``X_FORWARDED_FOR`` contains multiple addresses.

0.2.0 (2017-04-06)
++++++++++++++++++

* For Django 1.10+ support, changed from `object` to `django.utils.deprecation.MiddlewareMixin`
* Added PyPI trove classifiers for Django versions and more Python versions
* Updated `travis.yml` for more Python versions

0.1.4 (2016-07-02)
++++++++++++++++++

* Fixed an exception that could occur when non-utf8 bytes were included
  in user agent strings.

0.1.3.1 (2016-05-26)
++++++++++++++++++++

* Version bump to avoid PyPI's duplicate filename ban.

0.1.3 (2016-05-26)
++++++++++++++++++

* Added support to redirect to known view, or use custom status code settings.
* Added support for ignoring unauthenticated sessions.
* Fixed short circuit when REMOTE_ADDR was unknown.
* Dropped support for older Python versions: now requires 2.7, 3.3 or newer,
  with Django 1.8.

0.1.2 (2014-03-20)
++++++++++++++++++

* Resolved exception being raised when session switches from IPv4 to IPv6
* Python 3.4 support

0.1.1 (2014-02-18)
++++++++++++++++++

* Added missing netaddr requirement to setup.py.

0.1.0 (2014-02-17)
++++++++++++++++++

* First release on PyPI.
