import os
import PublicCloud
import unittest
import tempfile
import json
import random
import time
import datetime
import PublicCloud.x509 as x509
import base64
from Crypto.Hash import SHA
from Crypto.Cipher import AES
from sqlite3 import dbapi2 as sqlite3
from M2Crypto import X509, EVP, RSA, ASN1
from flask import Flask, request, session, g, redirect, url_for, abort, \
     render_template, flash, jsonify
     
import urllib
from M2Crypto.__m2crypto import sha1
import M2Crypto
class MarketPlaceTestCase(unittest.TestCase):

    def setUp(self):
        self.db_fd, PublicCloud.app.config['DATABASE'] = tempfile.mkstemp(prefix="Flask_Marketplace_")
        #print PublicCloud.app.config['DATABASE']
        PublicCloud.app.config['TESTING'] = True
        self.app = PublicCloud.app.test_client()
        PublicCloud.db.create_all()
        #self.CAcert = X509.load_cert('PublicCloud/cacert.crt')
        #self.pk = EVP.load_key("PublicCloud/ca_keypair")
        #print CAcert.__class__.__name__
        #print pk.__class__.__name__
        self.cert = X509.load_cert('PublicCloud/cert.crt')
        self.pk2 = EVP.load_key("PublicCloud/keypair")
        #self.cert , self.pk2 = x509.mk_temporary_cert(self.CAcert, self.pk, "Test_CN", "test Orga", "test orga unit") 
    def tearDown(self):
        os.close(self.db_fd)
        os.unlink(PublicCloud.app.config['DATABASE'])
        #PublicCloud.db.drop_all()
        
  #  def setUp(self):
       
        #

        
    
    def test_marketplace(self):
        rv = self.app.get('/marketplace')
        assert ('result'  in rv.data or "Empty" in rv.data)
    def test_Put_and_del_again(self):
        self.put_marketplace()
        self.put_marketplace()
        self.revoke_marketplace()
        self.revoke_marketplace()
    def test_Test_with_offers(self):
        self.put_marketplace()
        self.contract_put()
        self.contract_put()
        self.get_offers_per_marketplaceoffer()
        self.revoke_marketplace()
    def put_marketplace(self):
        deadline = str(time.time())
        self.pk2.sign_init()
        self.pk2.sign_update("A")
        self.pk2.sign_update("A")
        self.pk2.sign_update("1")
        self.pk2.sign_update("A")
        self.pk2.sign_update("A")
        self.pk2.sign_update(deadline)
        self.app.post("/add_marketplace",data=dict(
        name="A",
        firma="A",
        price=1,
        description="A",
        currency="A",
        deadline= deadline,
        x509=self.cert.as_pem(),
        signature = base64.b64encode(self.pk2.sign_final())
        ))
        
        rv = self.app.get('/marketplace')
        #print rv.data
        assert 'A'  in rv.data, "data not in database"
    def contrats_accept(self):
        
        pass
    def contract_put(self):
        #self.put_marketplace()
        rv = self.app.get('/marketplace')
        id=json.loads(rv.data)['result'][0]['id']
        
        raw_x509 = json.loads(rv.data)['result'][0]['x509']
        m_x509 = X509.load_cert_string(str(raw_x509))
        aes_key = SHA.new("".join([random.choice("ABCDEFGHIJKLMOPHRSTUVWXYZ1234567890") for a in range(64)])).hexdigest()
        rsa_key = m_x509.get_pubkey()
        iv = "".join([random.choice("ABCDEFGHIJKLMOPHRSTUVWXYZ1234567890") for a in range(16)])

        enc_aes_key = base64.b64encode(rsa_key.get_rsa().public_encrypt(aes_key[:16],M2Crypto.RSA.pkcs1_padding))
        
        cipher = AES.new(aes_key[:16], AES.MODE_CFB, iv)
        #cipher=M2Crypto.EVP.Cipher('aes_128_cfb',aes_key,iv, op=1)
        #cipher.update("Random_Data23456")
        cipher_text = base64.b64encode(cipher.encrypt("Cipher_text23456"))
        self.pk2.sign_init()
        self.pk2.sign_update(str(id))
        self.pk2.sign_update(iv)
        self.pk2.sign_update(enc_aes_key)
        self.pk2.sign_update(cipher_text)
        signature = base64.b64encode(self.pk2.sign_final())
        #[id,x509,key,IV,encypted_data]
        #[str(id),x509,key,IV,encypted_data]
        rv = self.app.post("/put_offer",data=dict(IV = iv,
                                                             id = id,
                                                             key = enc_aes_key,
                                                             x509 = self.cert.as_pem(),
                                                             signature = signature,
                                                             data = cipher_text))
        #self.test_revoke_marketplace()
        #print rv.data
        assert "OK" in rv.data
    
    def revoke_marketplace(self):
        rv = self.app.get('/marketplace')
        #print rv.data
        #print json.loads(rv.data)['result'][0]['id']
        self.pk2.sign_init()
        self.pk2.sign_update(str(json.loads(rv.data)['result'][0]['id']))
        nonce_str = "".join([random.choice("ABCDEFGHIJKLMOPHRSTUVWXYZ1234567890") for a in range(64)])
        self.pk2.sign_update(nonce_str)
        
        
        rv = self.app.post("/revoke_marketplace",data=dict(
                                                             id=json.loads(rv.data)['result'][0]['id'],
                                                             signature = base64.b64encode(self.pk2.sign_final()),
                                                             x509 = self.cert.as_pem(),
                                                             nonce = nonce_str))
        assert "OK" in rv.data
    def decrypt_offer(self,enc_key,data,iv):
        aes_key = M2Crypto.RSA.load_key('PublicCloud/keypair').private_decrypt(base64.b64decode(enc_key),M2Crypto.RSA.pkcs1_padding)
        cipher = AES.new(aes_key, AES.MODE_CFB, iv)
        data =  cipher.decrypt(base64.b64decode(data))
        return data
    def get_offers_per_marketplaceoffer(self):
        rv = self.app.get('/marketplace')
        id = json.loads(rv.data)['result'][0]['id']
        timestamp = str(time.time())
        x509 = self.cert
        self.pk2.sign_init()
        self.pk2.sign_update(str(id))
        self.pk2.sign_update(timestamp)
        signature = base64.b64encode(self.pk2.sign_final())
        rv = self.app.post("/get_offer",data=dict(    id = id,
                                                             x509 = self.cert.as_pem(),
                                                             signature = signature,
                                                             timestamp = timestamp))
        #print rv.data
        offer = json.loads(rv.data)['result'][0]
        data = self.decrypt_offer(offer['key'],offer['data'],offer['IV'])
        assert "Cipher_text23456" in data
        return offer,data

        #
        #assert 
#         rv = self.app.get('/marketplace')
#         #print rv.data
#         assert "Empty" in rv.data
#     
#    name =  request.args.get("name",type=str)
#    firma = request.args.get("firma",type=str)
#    price = request.args.get("price",type=int)
#    desciption = request.args.get("description",type=str)
#    currency = request.args.get("currency",type=str)
#    x509 = request.args.get("x509",type=str)
#    signature = request.args.get("signature",type=str)

if __name__ == '__main__':
    unittest.main()