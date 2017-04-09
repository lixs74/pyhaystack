#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Skyspark operation implementations.
"""

import fysom
import hmac
import base64
import hashlib
import re

from hashlib import sha1, sha256, pbkdf2_hmac
from binascii import b2a_hex, unhexlify, b2a_base64, hexlify

from ....util import state, scram
from ....util.asyncexc import AsynchronousException
from ...http.exceptions import HTTPStatusError

class Niagara4ScramAuthenticateOperation(state.HaystackOperation):
    """
    An implementation of the log-in procedure for Skyspark.  The procedure
    is as follows:

    1. Hello -> initiate the authentication conversation, sending the username we wish to authenticate as.
    2. First Message -> Send an authentication request to the server using the user name and a nonce
    3. Second Message -> Send an encoded message that proves we have the password.
    4. Retrieve the authToken send back by the server
    5. Optional -> Verifying that we are communicating with the correct server
    6. Using AuthToken to send request to the SkySpark Rest API: Authorization: BEARER authToken=aaabbbcccddd

    Future requests should the cookies returned.
    """

    _COOKIE_RE = re.compile(r'^cookie[ \t]*:[ \t]*([^=]+)=(.*)$')

    def __init__(self, session, retries=0):
        """
        Attempt to log in to the Skyspark server.

        :param session: Haystack HTTP session object.
        :param retries: Number of retries permitted in case of failure.
        """

        super(Niagara4ScramAuthenticateOperation, self).__init__()
        self._retries = retries
        self._session = session
        self._cookie = None
        self._nonce = None
        self._username = None
        self._user_salt = None
        self._digest = None

        self._algorithm = None
        self._handshake_token = None
        self._server_first_msg  = None
        self._server_nonce = None
        self._server_salt = None
        self._server_iterations = None
        self._auth_token = None
        self._auth = None

        self._login_uri = '%s'   % \
                (session._client.uri)
        self._state_machine = fysom.Fysom(
                initial='init', final='done',
                events=[
                    # Event               Current State         New State
                    ('get_new_session',   'init',               'newsession'),
                    ('do_hs_token',       'newsession',         'handshake_token'),
                    ('do_second_msg',     'handshake_token',    'second_msg'),
                    ('do_validate_second','second_msg',         'authenticated'),
                    ('login_done',        'authenticated',      'done'),
                    ('exception',         '*',                  'failed'),
                    ('retry',             'failed',             'newsession'),
                    ('abort',             'failed',             'done'),
                ], callbacks={
                    'onenternewsession':        self._do_new_session,
                    'onenterhandshake_token':   self._do_hs_token,
                    'onentersecond_msg':        self._do_second_msg,
                    'onenterauthenticated':     self._do_authenticated,
                    'onenterfailed':            self._do_fail_retry,
                    'onenterdone':              self._do_done,
                })

    def go(self):
        """
        Start the request.
        """
        # Are we logged in?
        print('Go')
        try:
            self._state_machine.get_new_session()
        except: # Catch all exceptions to pass to caller.
            self._state_machine.exception(result=AsynchronousException())

    def _do_new_session(self, event):
        """
        Test if server respond...
        """
        print('do_new', self._login_uri)
        try:
            self._session._get('%s/prelogin?clear=true' % self._login_uri,
                    callback=self._on_new_session,
                    cookies={}, headers={}, exclude_cookies=True,
                    exclude_headers=True, api=False)
        except: # Catch all exceptions to pass to caller.
            pass

    def _on_new_session(self, response):
        try:
            print(response.headers)
            
        
            self._state_machine.do_hs_token()
            
        except Exception as e: # Catch all exceptions to pass to caller.
            self._state_machine.exception(result=AsynchronousException())

    def _do_hs_token(self, event):
        """
        Test if server respond...
        """
        print('do_new', self._login_uri)
        try:
            self._session._post('%s/prelogin' % self._login_uri,
                    params={'j_username': self._session._username},
                    callback=self._on_hs_token,
                    cookies={}, 
                    headers={}, 
                    exclude_cookies=True,
                    exclude_headers=True, api=False)
        except: # Catch all exceptions to pass to caller.
            pass        

    def _on_hs_token(self, response):
        """
        Retrieve the log-in parameters.
        """
        print('on_new_session', response.headers)
        
        try:
            #if isinstance(response, AsynchronousException):
            #    response.reraise()
            
            self._nonce = scram.get_nonce_16()
            self._salt_username = scram.base64_no_padding(self._session._username)
            self.client_first_msg = "n=%s,r=%s" % (self._session._username, self._nonce)
            self._state_machine.do_second_msg()
        except Exception as e: # Catch all exceptions to pass to caller.
            self._state_machine.exception(result=AsynchronousException())

    def _do_second_msg(self, event):
        print('do_hs_token')
        msg = 'action=sendClientFirstMessage&clientFirstMessage=n,,%s' % self.client_first_msg
        payload={'action':msg.encode('utf-8')
                 }       
                    
        try:
            self._session._post('%s/j_security_check/%s' % (self._login_uri, msg.encode("utf-8")),
                    #params=payload,
                    callback=self._on_second_msg,
                    headers={"Content-Type": "application/x-niagara-login-support",
                             "Cookie": 'niagara_userid=%s' % self._session._username},
                    exclude_cookies=True, api=False)
        except Exception as e:
            self._state_machine.exception(result=AsynchronousException())

    def _on_second_msg(self, response):
        try:
            response.reraise() # ← AsynchronousException class
        except HTTPStatusError as e:
            if e.status != 401 and e.status != 303 and e.status != 500:
                raise
            try:
                print('do validate hs token', e.headers)
#        try:
#            response.reraise() # ← AsynchronousException class
#        except HTTPStatusError as e:
#            if e.status != 401 and e.status != 303:
#                raise

                self.jsession = get_jession(e.headers['Set-Cookie'])
    
                self.server_first_msg  = e.text
                print("ServerFirstMessage: " + self.server_first_msg)
                tab_response = self.server_first_msg.split(",")
                self.server_nonce = scram.regex_after_equal( tab_response[0] )
                self.server_salt = hexlify( scram.b64decode( scram.regex_after_equal( tab_response[1] ) ) )
                self.server_iterations = scram.regex_after_equal( tab_response[2] )
                self.algorithm_name = "sha256"
                self._algorithm = sha256
    
                #self._handshake_token = scram.regex_after_equal(header_response[0])
                self._state_machine.do_validate_second()
            except Exception as e:
                self._state_machine.exception(result=AsynchronousException())


    def _do_authenticated(self, event):
        print('do auth msg')
        self.salted_password = scram.salted_password( self.server_salt, self.server_iterations, self._algorithm_name, self._session.password )
        
        client_final_without_proof = "c=%s,r=%s" % ( scram.standard_b64encode(b'n,,').decode(), 
                                                    self.server_nonce )
        self.auth_msg = "%s,%s,%s" % ( self.client_first_msg, self.server_first_msg, 
                                      client_final_without_proof )
                
        
        self._client_second_msg = "n=%s,r=%s" % (self._session._username, self._nonce)
        client_second_msg_encoded = scram.base64_no_padding(self._client_second_msg)
        authMsg = "SCRAM handshakeToken=%s, data=%s" % (self._handshake_token , client_second_msg_encoded )
        client_proof = _createClientProof(self.salted_password, authMsg, self._algorithm)
        client_final_message = client_final_without_proof + ",p=" + client_proof
        final_msg = 'action=sendClientFinalMessage&clientFinalMessage=%s' % (client_final_message)
        
        try:
            # Post
            self._session._get('%s/haystack/about' % self._login_uri,
                    data=final_msg.encode("utf-8"),
                    callback=self._on_authenticated,
                    headers={"Content-Type": "application/x-niagara-login-support"},
                    cookies={"niagara_userid=%s" % self._session.username,
                             self.jsession},
                    exclude_cookies=True,
                    exclude_headers=True, api=False)
        except:
            self._state_machine.exception(result=AsynchronousException())

    def _on_authenticated(self, response):
        print('validate sec msg')
        try:
            response.reraise() # ← AsynchronousException class
        except HTTPStatusError as e:
            if e.status != 401 and e.status != 303:
                raise
            try:
#                header_response = e.headers['WWW-Authenticate']
#                tab_header = header_response.split(',')
#                server_data = scram.regex_after_equal(tab_header[0])
#                missing_padding = len(server_data) % 4
#                if missing_padding != 0:
#                    server_data += '='* (4 - missing_padding)
#                server_data = scram.b64decode(server_data).decode()
#                tab_response = server_data.split(',')
#                self._server_first_msg = server_data
#                self._server_nonce = scram.regex_after_equal(tab_response[0])
#                self._server_salt = scram.regex_after_equal(tab_response[1])
#                self._server_iterations = scram.regex_after_equal(tab_response[2])
#                if not self._server_nonce.startswith(self._nonce):
#                    raise Exception("Server returned an invalid nonce.")

#                self._state_machine.do_server_token()
                self._state_machine.login_done(result={'header': {"Content-Type", "application/x-niagara-login-support"},
                                                       'cookies': "niagara_userid=pyhaystack, JSESSIONID=%s" % self.jsession})

            except Exception as e:
                self._state_machine.exception(result=AsynchronousException())

    def _do_fail_retry(self, event):
        """
        Determine whether we retry or fail outright.
        """
        if self._retries > 0:
            self._retries -= 1
            self._state_machine.retry()
        else:
            self._state_machine.abort(result=event.result)

    def _do_done(self, event):
        """
        Return the result from the state machine.
        """
        self._done(event.result)

#def get_digest_info(param):
#    message = binary_encoding("%s:%s" % (param['username'], param['userSalt']))
#    password_buf = binary_encoding(param['password'])
#    hmac_final = base64.b64encode(hmac.new(key=password_buf, msg=message, digestmod=hashlib.sha1).digest())
#
#    digest_msg = binary_encoding('%s:%s' % (hmac_final.decode('utf-8'), param['nonce']))
#    digest = hashlib.sha1()
#    digest.update(digest_msg)
#    digest_final = base64.b64encode((digest.digest()))
#
#    res ={'hmac' : hmac_final.decode('utf-8'),
#         'digest' : digest_final.decode('utf-8'),
#         'nonce' : param['nonce']}
#    return res

def binary_encoding(string, encoding = 'utf-8'):
    """
    This helper function will allow compatibility with Python 2 and 3
    """
    try:
        return bytes(string, encoding)
    except TypeError: # We are in Python 2
        return str(string)

def get_jession(arg_header):
    #revDct = dict((val, key) for (key, val) in arg_header )
    jsession = arg_header.split(";")[0]
    print(jsession)
    return jsession
#    for key in revDct:
#        tmp_key = scram.regex_before_equal(key)
#        if tmp_key == "JSESSIONID=":
#            jsession = tmp_key = scram.regex_after_equal(key)
#            jsession = jsession.split(";")[0]
#            return "JSESSIONID=" + jsession
        
def _createClientProof(salted_password, auth_msg, algorithm):
    client_key          = hmac.new( unhexlify( salted_password ), "Client Key".encode('UTF-8'), algorithm).hexdigest()
    stored_key          = scram._hash_sha256( unhexlify(client_key) )
    client_signature    = hmac.new( unhexlify( stored_key ) , auth_msg.encode() , algorithm ).hexdigest()
    client_proof        = scram._xor (client_key, client_signature)
    return b2a_base64(unhexlify(client_proof)).decode()