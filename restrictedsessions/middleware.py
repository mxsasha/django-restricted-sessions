# -*- coding: utf-8 -*-
from netaddr import IPNetwork, IPAddress, AddrConversionError, AddrFormatError
import logging

from django.conf import settings
from django.contrib.auth import logout

SESSION_IP_KEY = '_restrictedsessions_ip'
SESSION_UA_KEY = '_restrictedsessions_ua'

logger = logging.getLogger('restrictedsessions')


class RestrictedSessionsMiddleware(object):
    def process_request(self, request):
        # No session -- nothing to check
        if not hasattr(request, 'session'):
            return

        # Only if option is enabled
        if getattr(settings, 'RESTRICTEDSESSIONS_AUTHED_ONLY', False):
            user = getattr(request, 'user', None)
            # No logged in user -- ignore checks
            if not user or not hasattr(user, 'is_authenticated') or not user.is_authenticated():
                return

        remote_ip = request.META.get(getattr(settings, 'RESTRICTEDSESSIONS_REMOTE_ADDR_KEY', 'REMOTE_ADDR'))
        user_agent = request.META.get('HTTP_USER_AGENT')

        orig_remote_ip = request.session.get(SESSION_IP_KEY)
        orig_user_agent = request.session.get(SESSION_UA_KEY)

        if not self.same_ip(orig_remote_ip, remote_ip):
            logger.warning("Destroyed session due to IP change: %s != %s", remote_ip, orig_remote_ip)
            logout(request)
        elif not self.same_ua(orig_user_agent, user_agent):
            logger.warning("Destroyed session due to user agent change: %s != %s", user_agent, orig_user_agent)
            logout(request)

        request.session[SESSION_IP_KEY] = remote_ip
        request.session[SESSION_UA_KEY] = user_agent

    @classmethod
    def same_ip(cls, orig_remote_ip, remote_ip):
        # Check is disabled -- always return true
        if not getattr(settings, 'RESTRICTEDSESSIONS_RESTRICT_IP', True):
            return True

        # No original IP or current IP is unknown
        if not orig_remote_ip or not remote_ip:
            return True

        session_network = IPNetwork(orig_remote_ip)
        remote_ip = IPAddress(remote_ip)
        try:
            session_network = session_network.ipv4()
            remote_ip = remote_ip.ipv4()
            session_network.prefixlen = getattr(settings, 'RESTRICTEDSESSIONS_IPV4_LENGTH', 32)
        except AddrConversionError:
            try:
                session_network.prefixlen = getattr(settings, 'RESTRICTEDSESSIONS_IPV6_LENGTH', 64)
            except AddrFormatError:
                # session_network must be IPv4, but remote_ip is IPv6
                return False

        # IP belongs to the same network
        return remote_ip in session_network

    @classmethod
    def same_ua(cls, orig_user_agent, user_agent):
        # Check is disabled -- always return true
        if not getattr(settings, 'RESTRICTEDSESSIONS_RESTRICT_UA', True):
            return True

        # User agent is identical
        return user_agent == orig_user_agent
