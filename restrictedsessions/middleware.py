# -*- coding: utf-8 -*-
from netaddr import IPNetwork, IPAddress, AddrConversionError, AddrFormatError
import logging

from django.http import HttpResponse
from django.core.urlresolvers import reverse
from django.shortcuts import redirect
from django.conf import settings

SESSION_IP_KEY = '_restrictedsessions_ip'
SESSION_UA_KEY = '_restrictedsessions_ua'
logger = logging.getLogger('restrictedsessions')


class RestrictedSessionsMiddleware(object):
    def process_request(self, request):
        # Short circuit when request doesn't have session
        if not hasattr(request, 'session'):
            return

        # Extract remote IP address for validation purposes
        remote_addr_key = getattr(settings, 'RESTRICTEDSESSIONS_REMOTE_ADDR_KEY', 'REMOTE_ADDR')
        remote_addr = request.META.get(remote_addr_key)

        # Clear the session and handle response when request doesn't validate
        if not self.validate_ip(request, remote_addr) or not self.validate_ua(request):
            logger.warning("Destroyed session due to invalid change of remote host or user agent")
            request.session.flush()
            redirect_view = getattr(settings, 'RESTRICTEDSESSIONS_REDIRECT_VIEW', None)
            if redirect_view:
                return redirect(reverse(redirect_view))
            else:
                status = getattr(settings, 'RESTRICTEDSESSIONS_FAILURE_STATUS', 400)
                return HttpResponse(status=status)

        # Set the UA/IP Address on the session since they validated correctly
        request.session[SESSION_IP_KEY] = remote_addr
        if request.META.get('HTTP_USER_AGENT'):
            request.session[SESSION_UA_KEY] = request.META['HTTP_USER_AGENT']

    def validate_ip(self, request, remote_ip):
        # When we aren't configured to restrict on IP address
        if not getattr(settings, 'RESTRICTEDSESSIONS_RESTRICT_IP', True):
            return True
        # When the IP address key hasn't yet been set on the request session
        if SESSION_IP_KEY not in request.session:
            return True
        # When there is no remote IP, check if one has been set on the session
        session_ip = request.session[SESSION_IP_KEY]
        if not remote_ip:
            if session_ip:  # session has remote IP value so validate :-(
                return False
            else:  # Session doesn't have remote IP value so possibly :-)
                return True

        # Compute fuzzy IP compare based on settings on compare sensitivity
        session_network = IPNetwork(session_ip)
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
        return remote_ip in session_network

    def validate_ua(self, request):
        # When we aren't configured to restrict on user agent
        if not getattr(settings, 'RESTRICTEDSESSIONS_RESTRICT_UA', True):
            return True
        # When the user agent key hasn't been set yet in the request session
        if SESSION_UA_KEY not in request.session:
            return True
        # Compare the new user agent value with what is known about the session
        return request.session[SESSION_UA_KEY] == request.META.get('HTTP_USER_AGENT')
