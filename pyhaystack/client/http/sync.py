# -*- coding: utf-8 -*-
"""
Synchronous HTTP client using Python Requests.
"""

from .base import HTTPClient, HTTPResponse
from .auth import BasicAuthenticationCredentials, \
                    DigestAuthenticationCredentials
from .exceptions import HTTPConnectionError, HTTPTimeoutError, \
        HTTPRedirectError, HTTPStatusError, HTTPBaseError

from ...util.asyncexc import AsynchronousException

import requests

class SyncHttpClient(HTTPClient):
    def __init__(self, **kwargs):
        self._session = requests.Session()
        super(SyncHttpClient, self).__init__(**kwargs)

    def _request(self, method, uri, callback, body,
            headers, cookies, auth, timeout, proxies,
            tls_verify, tls_cert):

        if auth is not None:
            if isinstance(auth, BasicAuthenticationCredentials):
                auth = requests.auth.HTTPBasicAuth(
                        auth.username, auth.password)
            elif isinstance(auth, DigestAuthenticationCredentials):
                auth = requests.auth.HTTPDigestAuth(
                        auth.username, auth.password)
            else:
                raise NotImplementedError(
                        '%s does not implement support for %s' % (
                            self.__class__.__name__,
                            auth.__class__.__name__))

        try:
            try:
                try:
                    response = self._session.request(
                            method=method, url=uri, data=body,
                            headers=headers, cookies=cookies,
                            auth=auth, timeout=timeout,
                            proxies=proxies, verify=tls_verify,
                            cert=tls_cert)
                    response.raise_for_status()
                except:
                    if self.log is not None:
                        self.log.debug('Exception in request %s of %s with '\
                                'body %r, headers %r, cookies %r, auth %r',
                                method, uri, body, headers, cookies, auth,
                                exc_info=1)
                    raise

            except requests.exceptions.HTTPError as e:
                raise HTTPStatusError(e.args[0], e.response.status_code, \
                        dict(e.response.headers), e.response.content)
            except requests.exceptions.Timeout as e:
                raise HTTPTimeoutError(e.strerror)
            except requests.exceptions.TooManyRedirects as e:
                raise HTTPRedirectError(e.message)
            except requests.exceptions.ConnectionError as e:
                raise HTTPConnectionError(e.strerror, e.errno)
            except requests.exceptions.RequestException:
                # TODO: handle this with a more specific exception
                raise HTTPBaseError(e.message)

            result = HTTPResponse(response.status_code,
                dict(response.headers), response.content,
                dict(response.cookies))
        except:
            # Catch all exceptions and forward those to the callback function
            result = AsynchronousException()

        try:
            callback(result)
        except: # pragma: no cover
            # This should not happen!
            if self.log:
                self.log.exception('Failure in callback with result: %r',
                        result)
