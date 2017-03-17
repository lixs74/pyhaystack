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

class SkysparkScramAuthenticateOperation(state.HaystackOperation):
    """
    An implementation of the log-in procedure for Skyspark.  The procedure
    is as follows:

    1.  
    2.  
    3.  
    4.  
    5.  
    6.  

    Future requests should the cookies returned.
    """

    _COOKIE_RE = re.compile(r'^cookie[ \t]*:[ \t]*([^=]+)=(.*)$')

    def __init__(self, session, retries=2):
        """
        Attempt to log in to the Skyspark server.

        :param session: Haystack HTTP session object.
        :param retries: Number of retries permitted in case of failure.
        """

        super(SkysparkScramAuthenticateOperation, self).__init__()
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
                    ('do_server_token',   'second_msg',         'server_token'),
                    ('login_done',        'server_token',       'done'),
                    ('exception',         '*',                  'failed'),
                    ('retry',             'failed',             'newsession'),
                    ('abort',             'failed',             'done'),
                ], callbacks={
                    'onenternewsession':        self._do_new_session,
                    'onenterhandshake_token':   self._do_hs_token,
                    'onentersecond_msg':        self._do_second_msg,
                    'onenterserver_token':      self._do_server_token,
                    'onenterfailed':            self._do_fail_retry,
                    'onenterdone':              self._do_done,
                })

    def go(self):
        """
        Start the request.
        """
        # Are we logged in?
        try:
            self._state_machine.get_new_session()
        except: # Catch all exceptions to pass to caller.
            self._state_machine.exception(result=AsynchronousException())

    def _do_new_session(self, event):
        """
        Request the log-in parameters.
        """
        try:
            self._session._get(self._login_uri,
                    callback=self._on_new_session,
                    
                    cookies={}, headers={}, exclude_cookies=True,
                    exclude_headers=True, api=False)
                    #args={'username': self._session._username},
        except: # Catch all exceptions to pass to caller.
            self._state_machine.exception(result=AsynchronousException())

    def _on_new_session(self, response):
        """
        Retrieve the log-in parameters.
        """
        try:
            if isinstance(response, AsynchronousException):
                response.reraise()
                
            self._nonce = scram.get_nonce()
            self._salt_username = scram.base64_no_padding(self._username)
            self._client_first_message = "HELLO username=%s" % (self._salt_username)
            print('new_session', self._nonce, self._client_first_message)
            self._state_machine.do_hs_token()
        except: # Catch all exceptions to pass to caller.
            self._state_machine.exception(result=AsynchronousException())
            
    def _do_hs_token(self, event):

        try:
            self._session._get(self._login_uri,
                    callback=self._validate_hs_token,
                    headers={"Authorization": self._client_first_message}, 
                    exclude_cookies=True,
                    exclude_headers=False, api=False)
        except:
            self._state_machine.exception(result=AsynchronousException())
        
    def _validate_hs_token(self, response):
        try:
            server_response      = response.headers['WWW-Authenticate']
            header_response      = server_response.split(',')
            algorithm = scram.regex_after_equal( header_response[1] )
            algorithm_name = algorithm.replace("-", "").lower()

            if algorithm_name == "sha256":
                self._algorithm = sha256
            elif algorithm_name == "sha1":
                self._algorithm = sha1
            else:
                raise Exception('SHA not implemented')
            self._handshake_token = scram.regex_after_equal(header_response[0])
            self._state_machine.do_second_msg()
        except:
            self._state_machine.exception(result=AsynchronousException())
        
    def _do_second_msg(self, event):
        client_second_msg = "n=%s,r=%s" % (self._username, self._nonce)
        client_second_msg_encoded = scram.base64_no_padding(client_second_msg)
        authMsg = "SCRAM handshakeToken=%s, data=%s" % (self._handshake_token , client_second_msg_encoded )
        try:
            # Post
            self._session._get(self._login_uri,
                    callback=self._validate_sec_msg,
                    headers={"Authorization": authMsg }, 
                    exclude_cookies=True,
                    exclude_headers=False, api=False)
        except:
            self._state_machine.exception(result=AsynchronousException())
        
    def _validate_sec_msg(self, response):
        try:
            header_response = response.headers['WWW-Authenticate']
            tab_header = header_response.split(',')
            server_data = scram.regex_after_equal(tab_header[0])
            missing_padding = len(server_data) % 4
            if missing_padding != 0:
                server_data += '='* (4 - missing_padding)
    
            server_data       = scram.b64decode(server_data).decode()
            tab_response      = server_data.split(',')
            self._server_first_msg  = server_data
            self._server_nonce      = scram.regex_after_equal(tab_response[0])
            self._server_salt       = scram.regex_after_equal(tab_response[1])
            self._server_iterations = scram.regex_after_equal(tab_response[2])
    
            if not self._server_nonce.startswith(self._nonce):
                raise Exception("Server returned an invalid nonce.")

            self._state_machine.do_server_token()
        except:
            self._state_machine.exception(result=AsynchronousException())

    def _do_server_token(self, event):
        try:
            client_final_no_proof = "c=%s,r=%s" % ( scram.standard_b64encode(b'n,,').decode() , self._server_nonce )
            auth_msg = "%s,%s,%s" % ( self._client_first_msg, self._server_first_msg, client_final_no_proof )
            client_key = hmac.new(unhexlify(self.salted_password( self._server_salt, self._server_iterations ) ), "Client Key".encode('UTF-8'), self._algorithm).hexdigest()
            stored_key = scram._hash_sha256(unhexlify(client_key))
            client_signature = hmac.new( unhexlify(stored_key), auth_msg.encode('utf-8'), self.algorithm).hexdigest()
            client_proof = scram._xor (client_key, client_signature)
            client_proof_encode = b2a_base64(unhexlify(client_proof)).decode()
            client_final = client_final_no_proof + ",p=" + client_proof_encode
            client_final_base64 = scram.base64_no_padding(client_final)
            final_msg = "scram handshaketoken=%s,data=%s" % (self._handshake_token , client_final_base64)
            
            self._session._get(self._login_uri,
                    callback=self._validate_sec_msg,
                    headers={"Authorization", final_msg}, 
                    exclude_cookies=True,
                    exclude_headers=True, api=False)
        
        except:
            self._state_machine.exception(result=AsynchronousException())

    def _validate_server_token(self, response):
        try:
            server_response = response.headers['Authentication-Info']
            tab_response = server_response.split(',')
            self._auth_token = scram.regex_after_equal(tab_response[0])
            print("Will use token: " + self._auth_token)
            self._auth = "BEARER authToken=%s" % self._auth_token

            self._state_machine.login_done(result={'Authorization': self._auth})
        except:
            pass
            
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
        print('Auth :', self._auth)
        self._done(event.result)
        
def get_digest_info(param):    
    message = binary_encoding("%s:%s" % (param['username'], param['userSalt']))
    password_buf = binary_encoding(param['password']) 
    hmac_final = base64.b64encode(hmac.new(key=password_buf, msg=message, digestmod=hashlib.sha1).digest())
    
    digest_msg = binary_encoding('%s:%s' % (hmac_final.decode('utf-8'), param['nonce']))
    digest = hashlib.sha1()
    digest.update(digest_msg)
    digest_final = base64.b64encode((digest.digest()))
    
    res ={'hmac' : hmac_final.decode('utf-8'),
         'digest' : digest_final.decode('utf-8'),
         'nonce' : param['nonce']}
    return res
    
def binary_encoding(string, encoding = 'utf-8'):
    """
    This helper function will allow compatibility with Python 2 and 3
    """
    try:
        return bytes(string, encoding)
    except TypeError: # We are in Python 2
        return str(string)
