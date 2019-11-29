# -*- coding: utf-8 -*-
from netaddr import IPNetwork, IPAddress, AddrConversionError, AddrFormatError
import logging

from django.http import HttpResponse
from django.urls import reverse
from django.shortcuts import redirect
from django.utils.encoding import force_text

from django.conf import settings

SESSION_IP_KEY = '_restrictedsessions_ip'
SESSION_UA_KEY = '_restrictedsessions_ua'

logger = logging.getLogger('restrictedsessions')


class RestrictedSessionsMiddleware(object):
    def process_request(self, request):
        # Short circuit when request doesn't have session
        if not hasattr(request, 'session'):
            return

        # Short circuit for option to require authed users
        user = getattr(request, 'user', None)
        if getattr(settings, 'RESTRICTEDSESSIONS_AUTHED_ONLY', False):
            # No logged in user -- ignore checks
            if not user or not hasattr(user, 'is_authenticated') or not user.is_authenticated:
                return

        # Extract remote IP address for validation purposes
        if getattr(settings, 'RESTRICTEDSESSIONS_REMOTE_ADDR_KEY', False):
            remote_addr_key = getattr(settings, 'RESTRICTEDSESSIONS_REMOTE_ADDR_KEY')
            remote_addr = request.META.get(remote_addr_key)
        else:
            if request.META.get('HTTP_X_FORWARDED_FOR', False):
                remote_addr = request.META.get('HTTP_X_FORWARDED_FOR')
                # in case of more than one proxy, XFF contain the list of the ip addresses in the format
                # client, proxy1, proxy2
                if ',' in remote_addr:
                    remote_addr = remote_addr.split(',')[0]
            else:
                remote_addr = request.META.get('REMOTE_ADDR')

        # Clear the session and handle response when request doesn't validate
        if not self.validate_ip(request, remote_addr) or not self.validate_ua(request):
            if getattr(settings, 'RESTRICTEDSESSIONS_AUTHED_ONLY', False):
                from django.contrib.auth import logout
                logout(request)
            else:  # logout(...) flushes the session so ensure it only happens once
                request.session.flush()
            logger.warning("Destroyed session due to invalid change of remote host or user agent")
            redirect_view = getattr(settings, 'RESTRICTEDSESSIONS_REDIRECT_VIEW', None)
            if redirect_view:
                return redirect(reverse(redirect_view))
            else:
                status = getattr(settings, 'RESTRICTEDSESSIONS_FAILURE_STATUS', 400)
                return HttpResponse(status=status)

        # Set the UA/IP Address on the session since they validated correctly
        request.session[SESSION_IP_KEY] = remote_addr
        if request.META.get('HTTP_USER_AGENT'):
            request.session[SESSION_UA_KEY] = force_text(request.META['HTTP_USER_AGENT'], errors='replace')

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
        is_ip_valid = remote_ip in session_network
        if not is_ip_valid:
            log_message = 'Invalid ip %s, it is not present in the session network: %s'
            logger.warning(log_message, remote_ip, session_network)
        return is_ip_valid

    def validate_ua(self, request):
        # When we aren't configured to restrict on user agent
        if not getattr(settings, 'RESTRICTEDSESSIONS_RESTRICT_UA', True):
            return True
        # When the user agent key hasn't been set yet in the request session
        if SESSION_UA_KEY not in request.session:
            return True
        # Compare the new user agent value with what is known about the session
        ua = force_text(request.META['HTTP_USER_AGENT'], errors='replace')
        session_ua = request.session[SESSION_UA_KEY]
        is_ua_valid = session_ua == ua
        if not is_ua_valid:
            log_message = 'Invalid ua %s, it does not match the session ua %s'
            encoded_ua = ua.encode('utf-8')
            encoded_session_ua = session_ua.encode('utf-8')
            logger.warning(log_message, encoded_ua, encoded_session_ua)
        return is_ua_valid
