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
from Crypto.PublicKey import RSA
from sqlite3 import dbapi2 as sqlite3
from M2Crypto import X509, EVP, ASN1
from flask import Flask, request, session, g, redirect, url_for, abort, \
     render_template, flash, jsonify
from paillier.paillier import *
import urllib
from M2Crypto.__m2crypto import sha1
import M2Crypto
from cronjob_accu import doCron


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
    
    def test_marketplace(self):
        rv = self.app.get('/marketplace')
        assert ('result'  in rv.data or "Empty" in rv.data)
    # TODO abgeschlossene testfaelle
    def test_Put_and_del_again(self):
        id1 = self.put_marketplace()
        id2 = self.put_marketplace()
        self.revoke_marketplace(id1)
        self.revoke_marketplace(id2)
    def test_Test_with_offers(self):
        id = self.put_marketplace()
        cid1 = self.contract_put(id)
        cid2 = self.contract_put(id)
        self.get_offers_per_marketplaceoffer(id)
        self.contrats_accept(cid1)
        self.revoke_marketplace(id)
    def test_data_flow(self):
        id = self.put_marketplace()
        cid = self.contract_put(id)
        self.contrats_accept(cid)
        self.dataflow_put(cid)
        self.dataflow_put(cid)
        self.dataflow_put(cid)
        self.dataflow_get(cid,"0")
        self.dataflow_get(cid,"1")
        self.revoke_marketplace(id)
        
        
        
    def put_marketplace(self):
        deadline = str(time.time())
        self.pk2.sign_init()
        self.pk2.sign_update("A")
        self.pk2.sign_update("1")
        self.pk2.sign_update("A")
        self.pk2.sign_update("A")
        self.pk2.sign_update(deadline)
        rv = self.app.post("/add_marketplace",data=dict(
        name="A",
        price=1,
        description="A",
        currency="A",
        deadline= deadline,
        x509=self.cert.as_pem(),
        signature = base64.b64encode(self.pk2.sign_final())
        ))
        return json.loads(rv.data)['result']['id']#rv.data
        #rv = self.app.get('/marketplace')
        #print rv.data
        #assert 'A'  in rv.data, "data not in database"
    def contrats_accept(self,id):
        offer, data  = self.get_offers_per_marketplaceoffer(id)
        id =  offer['id']
        nonce = "".join([random.choice("ABCDEFGHIJKLMOPHRSTUVWXYZ1234567890") for a in range(16)])
        timestamp = time.time()
        x509 = self.cert.as_pem()
        self.pk2.sign_init()
        self.pk2.sign_update(str(id))
        self.pk2.sign_update(nonce)
        self.pk2.sign_update(str(timestamp))
        signature = base64.b64encode(self.pk2.sign_final())
        rv = self.app.post("/accept_offer",data=dict(        id = id,
                                                             nonce = nonce,
                                                             timestamp = timestamp,
                                                             x509 = x509,
                                                             signature = signature))
        
        assert "OK" in rv.data
    def contract_put(self,marketplace_id):
        #self.put_marketplace()
        rv = self.app.get('/marketplace')
        id=marketplace_id#json.loads(rv.data)['result'][0]['id']
        
        raw_x509 = json.loads(rv.data)['result'][0]['x509']
        m_x509 = X509.load_cert_string(str(raw_x509))
        aes_key = SHA.new("".join([random.choice("ABCDEFGHIJKLMOPHRSTUVWXYZ1234567890") for _ in range(64)])).hexdigest()
        rsa_key = m_x509.get_pubkey()
        iv = gen_iv()
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
        #print cipher_text
        rv = self.app.post("/put_offer",data=dict(IV = iv,
                                                             id = id,
                                                             key = enc_aes_key,
                                                             x509 = self.cert.as_pem(),
                                                             signature = signature,
                                                             data = cipher_text))
        #self.test_revoke_marketplace()
        #print rv.data
        assert "id" in rv.data
        return json.loads(rv.data)['result']['id']
    
    def revoke_marketplace(self,marketplace_id):
        rv = self.app.get('/marketplace')
        #print rv.data
        #print json.loads(rv.data)['result'][0]['id']
        self.pk2.sign_init()
        self.pk2.sign_update(str(marketplace_id))
        nonce_str = "".join([random.choice("ABCDEFGHIJKLMOPHRSTUVWXYZ1234567890") for _ in range(64)])
        self.pk2.sign_update(nonce_str)
        
        
        rv = self.app.post("/revoke_marketplace",data=dict(
                                                             id=marketplace_id,
                                                             signature = base64.b64encode(self.pk2.sign_final()),
                                                             x509 = self.cert.as_pem(),
                                                             nonce = nonce_str))
        assert "OK" in rv.data
    def decrypt_offer(self,enc_key,data,iv):
        aes_key = M2Crypto.RSA.load_key('PublicCloud/keypair').private_decrypt(base64.b64decode(enc_key),M2Crypto.RSA.pkcs1_padding)
        cipher = AES.new(aes_key, AES.MODE_CFB, iv)
        data =  cipher.decrypt(base64.b64decode(data))
        return data
    def get_offers_per_marketplaceoffer(self,maketplace_id):
        #rv = self.app.get('/marketplace')
        id = maketplace_id#json.loads(rv.data)['result'][0]['id']
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
    def dataflow_put(self,contract_id):
        id = contract_id
        data = random_dataflow_creator()
        iv = gen_iv()
        key = base64.b64encode("01234567890123456")
        timestamp = str(int(time.time()))
        x509 = self.cert.as_pem()
        self.pk2.sign_init()
        self.pk2.sign_update(str(id))
        self.pk2.sign_update(data)
        self.pk2.sign_update(iv)
        self.pk2.sign_update(key)
        self.pk2.sign_update(timestamp)
        signature = base64.b64encode(self.pk2.sign_final())
        rv = self.app.post("/data_put",data=dict(    id = id,
                                                             x509 = self.cert.as_pem(),
                                                             data = data,
                                                             key = key,
                                                             IV = iv,
                                                             signature = signature,
                                                             timestamp = timestamp))
        #print rv.data
        assert "OK" in  rv.data
    def dataflow_get(self,contract_id,accu):
#         id = str(request.form['id'])
#         timestamp =  str(request.form['data'])
#         signature = str(request.form['signature'])
#         accu = str(request.form['raw'])
#         x509 = str(request.form['x509'])
        if accu == "1":
            doCron()
        id = contract_id
        timestamp = str(int(time.time()))
        x509 = self.cert.as_pem()
        accu = accu
        self.pk2.sign_init()
        self.pk2.sign_update(str(id))
        self.pk2.sign_update(accu)
        self.pk2.sign_update(timestamp)
        signature = base64.b64encode(self.pk2.sign_final())
        rv = self.app.post("/data_get",data=dict(    id = id,
                                                             x509 = self.cert.as_pem(),
                                                             accu = accu,
                                                             signature = signature,
                                                             timestamp = timestamp))
        print rv.data
# DONT DO THIS FOR PRODUCTIONAL PURPOSE, ONLY SECURERANDOM WITH RANDOM BYTEARRAY
def gen_iv():
    return "".join([random.choice("ABCDEFGHIJKLMOPHRSTUVWXYZ1234567890") for _ in range(16)])
def random_dataflow_creator():
    with open("PublicCloud/keypair","r") as f:
        rsa = RSA.importKey(f.read())
    priv = PrivateKey(rsa.key.p,rsa.key.q,rsa.key.n)
    pub =  PublicKey(rsa.key.n)
    rand1 = random.randrange(1,30)
    rand2 = random.randrange(1,30)
    rand3 = random.randrange(1,30)
    
    AccuData = {}
    AccuData['TestParamA'] = encrypt(pub, rand1)
    AccuData['TestParamB'] = encrypt(pub, rand2)
    AccuData['TestParamC'] = encrypt(pub, rand3)
    
    EncData = {}
    EncData['TestParamA'] = base64.b64encode(gen_iv())
    EncData['TestParamB'] = base64.b64encode(gen_iv())
    EncData['TestParamC'] = base64.b64encode(gen_iv())
    
    OpenData = {}
    OpenData['TestParamA'] = rand1
    OpenData['TestParamB'] = rand2
    OpenData['TestParamC'] = rand3
    
    return json.dumps({'AccuData'  : AccuData,
            'EncData'   : EncData,
            'OpenData'  : OpenData})


if __name__ == '__main__':
    unittest.main()