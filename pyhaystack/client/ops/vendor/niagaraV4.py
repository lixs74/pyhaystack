from binascii import b2a_hex, unhexlify, b2a_base64, hexlify, a2b_base64, a2b_hex
import requests
from base64 import standard_b64encode, b64decode, b64encode, urlsafe_b64encode, urlsafe_b64decode, decodestring
from hashlib import sha1, sha256, pbkdf2_hmac

import urllib.error as urlliberror2
import configparser as ConfigParser
import urllib.request as urllib2
import urllib.parse as urlib2_parse
import http.cookiejar
import struct
import logging
import hmac
import re
import os

class Niagara:
    def __init__(self, url, username, password):
        self.url            = url
        self.username       = username
        self.password       = password
        self.client_nonce   = self.get_nonce()
        self.algorithm_name = "sha256"
        self.algorithm      = sha256
        self.opener         = urllib2.build_opener(urllib2.HTTPHandler(debuglevel=4))

    def get_nonce(self):
        return urlsafe_b64encode( os.urandom(16) ).decode()

    def createClientFirstMessage(self):
        client_first_msg             = "n=%s,r=%s" % (self.username, self.client_nonce)
        return client_first_msg


    def _createClientFinalMessageWithoutProof(self, client_nonce, server_nonce):
        client_final_without_proof = "c=%s,r=%s" % ( standard_b64encode(b'n,,').decode(), server_nonce )
        return client_final_without_proof

    def serverFirstMessage(self, client_first_msg):
        urllib2.install_opener(urllib2.build_opener(urllib2.HTTPHandler(debuglevel=1)))
        params = 'action=sendClientFirstMessage&clientFirstMessage=n,,%s' % (client_first_msg)
        request = urllib2.Request(self.url, params.encode("utf-8") )
        request.add_header("Content-Type", "application/x-niagara-login-support" )

        self.opener.addheaders.append(("Cookie", "niagara_userid=pyhaystack"))

        try:
            result = self.opener.open(request)
            self.jsession = self.get_jession( result.getheaders() )
            server_first_msg  = result.read().decode("utf8")
            print("ServerFirstMessage: " + server_first_msg)
            tab_response      = server_first_msg.split(",")
            server_nonce      = self.regex_after_equal( tab_response[0] )
            server_salt       = hexlify( b64decode( self.regex_after_equal( tab_response[1] ) ) )
            server_iterations = self.regex_after_equal( tab_response[2] )
            return ( server_first_msg, server_nonce, server_salt, server_iterations )

        except urlliberror2.HTTPError as e:
            print(e)

    def _createAuthMessage(self, client_first_msg, server_first_msg, client_final_without_proof ):
        auth_msg = "%s,%s,%s" % ( client_first_msg, server_first_msg, client_final_without_proof )
        return auth_msg

    def _createClientProof(self, salted_password, auth_msg):
        client_key          = hmac.new( unhexlify( salted_password ), "Client Key".encode('UTF-8'), self.algorithm).hexdigest()
        stored_key          = self._hash_sha256( unhexlify(client_key) )
        client_signature    = hmac.new( unhexlify( stored_key ) , auth_msg.encode() , self.algorithm ).hexdigest()
        client_proof        = self._xor (client_key, client_signature)
        return b2a_base64(unhexlify(client_proof)).decode()

    def scram_authentication(self):
        urllib2.install_opener(urllib2.build_opener(urllib2.HTTPHandler(debuglevel=1)))
        client_first_msg                                                   = self.createClientFirstMessage()
        ( server_first_msg, server_nonce, server_salt, server_iterations ) = self.serverFirstMessage( client_first_msg )
        salted_password                                                    = self.salted_password( server_salt, server_iterations )
        client_final_without_proof                                         = self._createClientFinalMessageWithoutProof( self.client_nonce, server_nonce )
        auth_msg                                                           = self._createAuthMessage( client_first_msg, server_first_msg, client_final_without_proof )
        client_proof                                                       = self._createClientProof( salted_password, auth_msg ) #Good
        client_final_message                                               = client_final_without_proof + ",p=" + client_proof
        final_msg = 'action=sendClientFinalMessage&clientFinalMessage=%s' % (client_final_message)
        request = urllib2.Request(self.url, final_msg.encode("utf-8") )
        request.add_header("Content-Type", "application/x-niagara-login-support" )


        self.opener.addheaders.append(("Cookie", "niagara_userid=pyhaystack"))
        self.opener.addheaders.append(("Cookie", self.jsession))

        #There is an other cookie => JSESSIONID=653a6873c4dd57dc82e4779f5b973a4fda3d114ee29e07377b
        #request.add_header("Cookie", "niagara_userid = pyhaystack" )
        #request.add_header("SET-Cookie", self.jsession )

        #print("Client Proof: " + client_proof) #good
        #print("client_first_msg: " + client_first_msg)
        #print("server_first_msg: " + server_first_msg)
        #print("client_final_without_proof: " + client_final_without_proof)
        #print("auth_msg: " + auth_msg)
        print("final_msg: " + final_msg)

        try:
            result   = self.opener.open(request)
            print( result.read() )
        except urlliberror2.HTTPError as e:
            print(e)


    def _hash_sha256(self, str):
        hashFunc = self.algorithm()
        hashFunc.update( str )
        return hashFunc.hexdigest()

    def salted_password(self, salt, iterations):
        dk = pbkdf2_hmac( self.algorithm_name, self.password.encode(), urlsafe_b64decode(salt), int(iterations))
        encrypt_password = hexlify(dk)
        return encrypt_password

    def base64_no_padding(self, s):
        encoded_str = urlsafe_b64encode(s.encode())
        encoded_str = encoded_str.decode().replace("=", "")
        return encoded_str

    def regex_after_equal(self, s):
        tmp_str = re.search( "\=(.*)$" ,s, flags=0)
        return tmp_str.group(1)

    def regex_before_equal(self, s):
        tmp_str = re.search( ".+?(=)" ,s, flags=0)
        if tmp_str:
            return tmp_str.group(0)
        else:
            return

    def get_jession(self, arg_header):
        revDct = dict((val, key) for (key, val) in arg_header )

        for key in revDct:
            tmp_key = self.regex_before_equal(key)
            if tmp_key == "JSESSIONID=":
                jsession = tmp_key = self.regex_after_equal(key)
                jsession = jsession.split(";")[0]
                return "JSESSIONID=" + jsession

    def _xor(self, s1, s2):
        return hex(int(s1, 16) ^ int(s2, 16))[2:]


niagara = Niagara("http://10.30.1.121/j_security_check/", "admin", "J2l1J5" )
auth_token = niagara.scram_authentication()
