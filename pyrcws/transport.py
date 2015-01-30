# coding: utf-8
import io

import requests

from suds.transport.https import HttpAuthenticated
from suds.transport import Reply


def getTransport(cert_file):
    return RequestsTransport(cert_file)


class RequestsTransport(HttpAuthenticated):
    def __init__(self, cert, **kwargs):
        self.cert = cert
        # super won't work because not using new style class
        HttpAuthenticated.__init__(self, **kwargs)


    def addcredentials(self, request):
        user = self.options.username
        pwd = self.options.password
        if user is not None:
            self.pm.add_password(None, request.url, user, pwd)


    def open(self, request):
        self.addcredentials(request)
        resp = requests.get(request.url, data=request.message, headers=request.headers, verify=self.cert)
        result = io.StringIO(resp.content.decode('utf-8'))
        return result

    def send(self, request):
        self.addcredentials(request)
        resp = requests.post(request.url, data=request.message, headers=request.headers, verify=self.cert)
        result = Reply(resp.status_code, resp.headers, resp.content)
        return result

