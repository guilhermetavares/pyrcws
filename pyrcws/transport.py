# coding: utf-8
import urllib2 as u2
from suds.client import Client
from suds.transport.http import HttpTransport
import httplib
import socket


def getTransport(cert_file):
    return HTTPSClientCertTransport(cert_file)


class HTTPSClientAuthHandler(u2.HTTPSHandler):
    def __init__(self, key, cert):
        u2.HTTPSHandler.__init__(self)
        self.key = key
        self.cert = cert

    def https_open(self, req):
        # Rather than pass in a reference to a connection class, we pass in
        # a reference to a function which, for all intents and purposes,
        # will behave as a constructor
        return self.do_open(self.getConnection, req)

    def getConnection(self, host, timeout=300):
        return httplib.HTTPSConnection(
            host,
            cert_file=self.cert)


class HTTPSClientCertTransport(HttpTransport):
    def __init__(self, cert, key=None, proxy_settings=None, *args, **kwargs):
        HttpTransport.__init__(self, *args, **kwargs)
        if key:
            self.key = key
        else:
            self.key = cert
        self.cert = cert
        self.proxy_settings = proxy_settings

    def u2open(self, u2request):
        """
        Open a connection.
        @param u2request: A urllib2 request.
        @type u2request: urllib2.Requet.
        @return: The opened file-like urllib2 object.
        @rtype: fp
        """
        tm = self.options.timeout

        https_client_auth_handler = HTTPSClientAuthHandler(self.key,
                                                           self.cert)

        # Add a proxy handler if the proxy settings is specified.
        # Otherwise, just use the HTTPSClientAuthHandler.
        if self.proxy_settings:
            proxy_handler = u2.ProxyHandler(self.proxy_settings)
            url = u2.build_opener(proxy_handler, https_client_auth_handler)
        else:
            url = u2.build_opener(https_client_auth_handler)

        url = u2.build_opener()

        if self.u2ver() < 2.6:
            socket.setdefaulttimeout(tm)
            return url.open(u2request)
        else:
            return url.open(u2request, timeout=tm)
