# -*- coding: utf-8 -*-
from netaddr import IPNetwork, IPAddress, AddrConversionError, AddrFormatError
import logging

from django.http import HttpResponseBadRequest
from django.conf import settings
from django.contrib.auth import logout

SESSION_IP_KEY = '_restrictedsessions_ip'
SESSION_UA_KEY = '_restrictedsessions_ua'
AUTHED_ONLY = getattr(settings, 'RESTRICTEDSESSIONS_AUTHED_ONLY', False)
IP_HEADER = getattr(settings, 'RESTRICTEDSESSIONS_REMOTE_ADDR_KEY', 'REMOTE_ADDR')
UA_HEADER = 'HTTP_USER_AGENT'
IPV4_LENGTH = getattr(settings, 'RESTRICTEDSESSIONS_IPV4_LENGTH', 32)
IPV6_LENGTH = getattr(settings, 'RESTRICTEDSESSIONS_IPV6_LENGTH', 64)

logger = logging.getLogger('restrictedsessions')


class RestrictedSessionsMiddleware(object):
    def process_request(self, request):
        if not hasattr(request, 'session'):
            return

        # Only perform check if there is a user and user is authenticated
        user = getattr(request, 'user', None)
        if AUTHED_ONLY and (user is None or not user.is_authenticated()):
            return

        remote_addr = request.META.get(IP_HEADER)
        if not remote_addr:
            return

        if not self.validate_ip(request, remote_addr) or not self.validate_ua(request):
            logger.warning("Destroyed session due to invalid change of remote host or user agent. IP: {ip}".format(ip=remote_addr))
            # Django would take care about flushing session and checking user
            logout(request)

        request.session[SESSION_IP_KEY] = remote_addr
        if request.META.get(UA_HEADER):
            request.session[SESSION_UA_KEY] = request.META[UA_HEADER]

    def validate_ip(self, request, remote_ip):
        if not getattr(settings, 'RESTRICTEDSESSIONS_RESTRICT_IP', True) or not SESSION_IP_KEY in request.session:
            return True

        session_network = IPNetwork(request.session[SESSION_IP_KEY])
        remote_ip = IPAddress(remote_ip)
        try:
            session_network = session_network.ipv4()
            remote_ip = remote_ip.ipv4()
            session_network.prefixlen = IPV4_LENGTH
        except AddrConversionError:
            try:
                session_network.prefixlen = IPV6_LENGTH
            except AddrFormatError:
                # session_network must be IPv4, but remote_ip is IPv6
                return False
        return remote_ip in session_network

    def validate_ua(self, request):
        if not getattr(settings, 'RESTRICTEDSESSIONS_RESTRICT_UA', True) or not SESSION_UA_KEY in request.session:
            return True
        return request.session[SESSION_UA_KEY] == request.META.get(UA_HEADER)
