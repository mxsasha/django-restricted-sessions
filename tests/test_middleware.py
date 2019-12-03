#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
test_django-restricted-sessions
------------

Tests for `django-restricted-sessions` models module.
"""

from __future__ import unicode_literals

import unittest

from django.test.client import RequestFactory
from django.test.utils import override_settings
from django.contrib.auth.models import User, AnonymousUser
from django.contrib.sessions.middleware import SessionMiddleware
from django.http import HttpResponse

from restrictedsessions import middleware


class TestRestrictedsessionsMiddleware(unittest.TestCase):

    def setUp(self):
        self.middleware = middleware.RestrictedSessionsMiddleware()
        self.factory = RequestFactory()
        self.request = self.factory.get('/')

    def test_without_session(self):
        self.assertTrue(self.middleware.process_request(self.request) is None)

    def test_without_remote_addr(self):
        self.add_session_to_request()
        del self.request.META['REMOTE_ADDR']
        self.assertTrue(self.middleware.process_request(self.request) is None)
        self.assertTrue(self.request.session.get(middleware.SESSION_IP_KEY) is None)
        self.assertTrue(self.request.session.get(middleware.SESSION_UA_KEY) is None)

    def test_without_remote_addr_still_check_user_agent(self):
        # Given: No remote IP incoming
        self.add_session_to_request()
        del self.request.META['REMOTE_ADDR']
        # Given: First request has an arbitrary User Agent string
        initial_user_agent = 'ua-initial'
        self.request.META['HTTP_USER_AGENT'] = initial_user_agent
        # When: the middleware first sees the request
        self.assertTrue(self.middleware.process_request(self.request) is None)
        # Then: it sets only the user agent string
        self.assertTrue(self.request.session.get(middleware.SESSION_IP_KEY) is None)
        self.assertEqual(self.request.session.get(middleware.SESSION_UA_KEY), initial_user_agent)

        # Given: A second request is made with a new user agent string
        different_user_agent = 'us-changed'
        self.request.META['HTTP_USER_AGENT'] = different_user_agent
        # When: the middleware first sees the request
        response = self.middleware.process_request(self.request)
        # Then: there was an HttpResponse returned from middleware
        self.assertIsInstance(response, HttpResponse)
        # Then: the response was a HTTP 400 status response by default
        self.assertEqual(response.status_code, 400)

    @override_settings(RESTRICTEDSESSIONS_FAILURE_STATUS=404)
    def test_without_remote_addr_still_check_user_agent_when_configured_status(self):
        # Given: No remote IP incoming
        self.add_session_to_request()
        del self.request.META['REMOTE_ADDR']
        # Given: First request has an arbitrary User Agent string
        initial_user_agent = 'ua-initial'
        self.request.META['HTTP_USER_AGENT'] = initial_user_agent
        # When: the middleware first sees the request
        self.assertTrue(self.middleware.process_request(self.request) is None)
        # Then: it sets only the user agent string
        self.assertTrue(self.request.session.get(middleware.SESSION_IP_KEY) is None)
        self.assertEqual(self.request.session.get(middleware.SESSION_UA_KEY), initial_user_agent)

        # Given: A second request is made with a new user agent string
        different_user_agent = 'us-changed'
        self.request.META['HTTP_USER_AGENT'] = different_user_agent
        # When: the middleware first sees the request
        response = self.middleware.process_request(self.request)
        # Then: there was an HttpResponse returned from middleware
        self.assertIsInstance(response, HttpResponse)
        # Then: the response was a HTTP 400 status response by default
        self.assertEqual(response.status_code, 404)

    @override_settings(RESTRICTEDSESSIONS_REDIRECT_VIEW='test_view')
    def test_without_remote_addr_still_check_user_agent_when_redirect(self):
        # Given: No remote IP incoming
        self.add_session_to_request()
        del self.request.META['REMOTE_ADDR']
        # Given: First request has an arbitrary User Agent string
        initial_user_agent = 'ua-initial'
        self.request.META['HTTP_USER_AGENT'] = initial_user_agent
        # When: the middleware first sees the request
        self.assertTrue(self.middleware.process_request(self.request) is None)
        # Then: it sets only the user agent string
        self.assertTrue(self.request.session.get(middleware.SESSION_IP_KEY) is None)
        self.assertEqual(self.request.session.get(middleware.SESSION_UA_KEY), initial_user_agent)

        # Given: A second request is made with a new user agent string
        different_user_agent = 'us-changed'
        self.request.META['HTTP_USER_AGENT'] = different_user_agent
        # When: the middleware first sees the request
        response = self.middleware.process_request(self.request)
        # Then: there was an HttpResponse returned from middleware
        self.assertIsInstance(response, HttpResponse)
        # Then: the response was an HTTP redirect to the test view
        self.assertEqual(response.status_code, 302)
        # Then: the URL is the view from the settings override
        self.assertEqual(response.url, '/test_view/')

    @override_settings(RESTRICTEDSESSIONS_REMOTE_ADDR_KEY='CUSTOM_REMOTE_ADDR')
    def test_without_remote_addr_with_custom_key(self):
        self.add_session_to_request()
        self.assertTrue(self.middleware.process_request(self.request) is None)
        self.assertTrue(self.request.session.get(middleware.SESSION_IP_KEY) is None)
        self.assertTrue(self.request.session.get(middleware.SESSION_UA_KEY) is None)

    def test_saves_with_remote_addr(self):
        self.add_session_to_request()
        self.assertTrue(self.middleware.process_request(self.request) is None)
        self.assertEqual(self.request.session[middleware.SESSION_IP_KEY], self.request.META['REMOTE_ADDR'])
        self.request.META['HTTP_USER_AGENT'] = 'test-ua'
        self.assertTrue(self.middleware.process_request(self.request) is None)
        self.assertEqual(self.request.session[middleware.SESSION_IP_KEY], self.request.META['REMOTE_ADDR'])
        self.assertEqual(self.request.session[middleware.SESSION_UA_KEY], self.request.META['HTTP_USER_AGENT'])

    @override_settings(RESTRICTEDSESSIONS_REMOTE_ADDR_KEY='CUSTOM_REMOTE_ADDR')
    def test_saves_with_remote_addr_with_custom_key(self):
        self.add_session_to_request()
        self.request.META['CUSTOM_REMOTE_ADDR'] = self.request.META['REMOTE_ADDR']
        del self.request.META['REMOTE_ADDR']
        self.assertTrue(self.middleware.process_request(self.request) is None)
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

    def test_validates_multiple_addresses(self):
        self._remote_addr_test(session_ip='127.0.0.1', valid='127.0.0.1, 192.0.2.1',
                               invalid='127.0.0.2, 127.0.0.1')

    def test_validates_ipv4_to_ipv6(self):
        self._remote_addr_test(session_ip='127.0.0.1', valid='127.0.0.1', invalid='2001:db8::1')

    def test_validates_ipv6_to_ipv4(self):
        self._remote_addr_test(session_ip='2001:db8::1', valid='2001:db8::1', invalid='127.0.0.1')

    def _remote_addr_test(self, session_ip, valid, invalid=None):
        self.add_session_to_request()
        self.request.session[middleware.SESSION_IP_KEY] = session_ip
        self.request.META['REMOTE_ADDR'] = valid
        self.assertTrue(self.middleware.process_request(self.request) is None)

        if invalid:
            self.request.session['canary'] = 'canary'
            self.request.META['REMOTE_ADDR'] = invalid
            self.assertEqual(self.middleware.process_request(self.request).status_code, 400)
            self.assertFalse('canary' in self.request.session)

    def test_ip_was_known_now_absent(self):
        # Given: A session with a known ip
        session_ip = '127.0.0.1'
        self.add_session_to_request()
        self.request.session[middleware.SESSION_IP_KEY] = session_ip
        # When: Incoming request doesn't have Remote address
        self.request.META['REMOTE_ADDR'] = None
        response = self.middleware.process_request(self.request)
        # Then: there was an HttpResponse returned from middleware
        self.assertIsInstance(response, HttpResponse)
        # Then: the response defaults to 400 error
        self.assertEqual(response.status_code, 400)

    def test_validates_ua(self):
        self.add_session_to_request()
        # Non-UTF8 chars should be replaced with \ufffd (replacement character).
        self.request.META['HTTP_USER_AGENT'] = b'test-ua1\xd9'
        self.request.session[middleware.SESSION_UA_KEY] = 'test-ua1\ufffd'
        self.assertTrue(self.middleware.process_request(self.request) is None)

        self.request.META['HTTP_USER_AGENT'] = 'test-ua1'
        self.assertEqual(self.middleware.process_request(self.request).status_code, 400)

    @override_settings(RESTRICTEDSESSIONS_RESTRICT_IP=False)
    def test_disable_ip_validation(self):
        self._remote_addr_test(session_ip='127.0.0.1', valid='192.0.2.0')

    @override_settings(RESTRICTEDSESSIONS_RESTRICT_UA=False)
    def test_disable_ua_validation(self):
        self.add_session_to_request()
        self.request.session[middleware.SESSION_UA_KEY] = 'test-ua1'
        self.request.META['HTTP_USER_AGENT'] = 'test-ua2'
        self.assertTrue(self.middleware.process_request(self.request) is None)

    @override_settings(RESTRICTEDSESSIONS_AUTHED_ONLY=True)
    def test_only_authed_users_setting(self):
        self.add_session_to_request()
        self.request.user = AnonymousUser()
        self.assertIsNone(self.middleware.process_request(self.request))

        self.request.user = User(username='test')
        self.assertIsNone(self.middleware.process_request(self.request))
        self._remote_addr_test(session_ip='127.0.0.1', valid='127.0.0.1',
                               invalid='127.0.0.2')
        self.assertIsInstance(self.request.user, AnonymousUser)

    def add_session_to_request(self):
        middleware = SessionMiddleware()
        middleware.process_request(self.request)
        self.request.session.save()
        # Trigger saving the session
        self.request.session['foo'] = 'foo'

