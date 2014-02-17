#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
test_django-restricted-sessions
------------

Tests for `django-restricted-sessions` models module.
"""

import unittest

from django.test.client import RequestFactory
from django.test.utils import override_settings
from django.contrib.sessions.middleware import SessionMiddleware

from restrictedsessions import middleware


class TestRestrictedsessionsMiddleware(unittest.TestCase):

    def setUp(self):
        self.middleware = middleware.RestrictedSessionsMiddleware()
        self.factory = RequestFactory()
        self.request = self.factory.get('/')

    def test_without_session(self):
        self.assertIsNone(self.middleware.process_request(self.request))

    def test_without_remote_addr(self):
        self.add_session_to_request()
        del self.request.META['REMOTE_ADDR']
        self.assertIsNone(self.middleware.process_request(self.request))
        self.assertIsNone(self.request.session.get(middleware.SESSION_IP_KEY))
        self.assertIsNone(self.request.session.get(middleware.SESSION_UA_KEY))

    @override_settings(RESTRICTEDSESSIONS_REMOTE_ADDR_KEY='CUSTOM_REMOTE_ADDR')
    def test_without_remote_addr_with_custom_key(self):
        self.add_session_to_request()
        self.assertIsNone(self.middleware.process_request(self.request))
        self.assertIsNone(self.request.session.get(middleware.SESSION_IP_KEY))
        self.assertIsNone(self.request.session.get(middleware.SESSION_UA_KEY))

    def test_saves_with_remote_addr(self):
        self.add_session_to_request()
        self.assertIsNone(self.middleware.process_request(self.request))
        self.assertEqual(self.request.session[middleware.SESSION_IP_KEY], self.request.META['REMOTE_ADDR'])
        self.request.META['HTTP_USER_AGENT'] = 'test-ua'
        self.assertIsNone(self.middleware.process_request(self.request))
        self.assertEqual(self.request.session[middleware.SESSION_IP_KEY], self.request.META['REMOTE_ADDR'])
        self.assertEqual(self.request.session[middleware.SESSION_UA_KEY], self.request.META['HTTP_USER_AGENT'])

    @override_settings(RESTRICTEDSESSIONS_REMOTE_ADDR_KEY='CUSTOM_REMOTE_ADDR')
    def test_saves_with_remote_addr_with_custom_key(self):
        self.add_session_to_request()
        self.request.META['CUSTOM_REMOTE_ADDR'] = self.request.META['REMOTE_ADDR']
        del self.request.META['REMOTE_ADDR']
        self.assertIsNone(self.middleware.process_request(self.request))
        self.assertEqual(self.request.session[middleware.SESSION_IP_KEY], self.request.META['CUSTOM_REMOTE_ADDR'])

    def test_validates_ipv4(self):
        self._remote_addr_test(session_ip='127.0.0.1', valid='127.0.0.1', invalid='127.0.0.2')

    @override_settings(RESTRICTEDSESSIONS_IPV4_LENGTH=24)
    def test_validates_ipv4_subnet(self):
        self._remote_addr_test(session_ip='127.0.0.1', valid='127.0.0.255', invalid='127.0.1.1')

    def test_validates_ipv6(self):
        self._remote_addr_test(
            session_ip='2001:db8:0:0:0:0:0:1',
            valid='2001:db8:0:0:ffff:ffff:ffff:ffff',
            invalid='2001:db8:0:1:0:0:0:1'
        )

    @override_settings(RESTRICTEDSESSIONS_IPV6_LENGTH=128)
    def test_validates_ipv6_custom_length(self):
        self._remote_addr_test(
            session_ip='2001:db8:0:0:0:0:0:1',
            valid='2001:db8:0:0:0:0:0:1',
            invalid='2001:db8:0:0:0:0:0:2'
        )

    def test_validates_ipv6_mapped_ipv4(self):
        self._remote_addr_test(
            session_ip='::ffff:127.0.0.1',
            valid='::ffff:127.0.0.1',
            invalid='::ffff:127.0.0.2'
        )

    def _remote_addr_test(self, session_ip, valid, invalid=None):
        self.add_session_to_request()
        self.request.session[middleware.SESSION_IP_KEY] = session_ip
        self.request.META['REMOTE_ADDR'] = valid
        self.assertIsNone(self.middleware.process_request(self.request))

        if invalid:
            self.request.session['canary'] = 'canary'
            self.request.META['REMOTE_ADDR'] = invalid
            self.assertEqual(self.middleware.process_request(self.request).status_code, 400)
            self.assertFalse('canary' in self.request.session)

    def test_validates_ua(self):
        self.add_session_to_request()
        self.request.META['HTTP_USER_AGENT'] = 'test-ua1'
        self.request.session[middleware.SESSION_UA_KEY] = 'test-ua1'
        self.assertIsNone(self.middleware.process_request(self.request))

        self.request.META['HTTP_USER_AGENT'] = 'test-ua2'
        self.assertEqual(self.middleware.process_request(self.request).status_code, 400)

    @override_settings(RESTRICTEDSESSIONS_RESTRICT_IP=False)
    def test_disable_ip_validation(self):
        self._remote_addr_test(session_ip='127.0.0.1', valid='192.0.2.0')

    @override_settings(RESTRICTEDSESSIONS_RESTRICT_UA=False)
    def test_disable_ua_validation(self):
        self.add_session_to_request()
        self.request.session[middleware.SESSION_UA_KEY] = 'test-ua1'
        self.request.META['HTTP_USER_AGENT'] = 'test-ua2'
        self.assertIsNone(self.middleware.process_request(self.request))

    def add_session_to_request(self):
        middleware = SessionMiddleware()
        middleware.process_request(self.request)
        self.request.session.save()
        # Trigger saving the session
        self.request.session['foo'] = 'foo'
