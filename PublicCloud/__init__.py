import os
import base64
import flask
import json
#from flask import Flask, jsonify, render_template, request
from flask.ext.sqlalchemy import SQLAlchemy
import datetime
from M2Crypto import X509, EVP, RSA, ASN1
from sqlite3 import dbapi2 as sqlite3
import time
from flask import Flask, request, session, g, redirect, url_for, abort, \
     render_template, flash, jsonify
import urllib
import PublicCloud.Cloud_logger



app = Flask(__name__)
app.config['DEBUG'] = True  # TODO: disable before deploying on production server
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///{0}'.format(os.path.join('..', 'test.db'))
#app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://clouduser:Loo2keep@141.28.104.240/clouddatabase'
db = SQLAlchemy(app)
CAcert = X509.load_cert('PublicCloud/cacert.crt')
CApk = EVP.load_key("PublicCloud/ca_keypair")
STATES = ["OPEN","CLOSED","ACTIVE"]
class Marketplace(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128))
    #firma = db.Column(db.String(128))
    price = db.Column(db.Integer)
    desciption = db.Column(db.String(200))
    date = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    deadline =  db.Column(db.DateTime, default=datetime.datetime.utcnow)
    currency = db.Column(db.String(3),default="EUR")
    x509 = db.Column(db.String(1000))
    signature = db.Column(db.String(1000))
    state = db.Column(db.Enum(*STATES),default="OPEN")
    contracts = db.relationship('Contract', backref='marketplace',
                                lazy='dynamic',cascade="all, delete-orphan")
    @property
    def to_json(self):
        return {
           'id'         : self.id,
           'name'       : self.name,
           'firma'      : self.firma,
           'price'      : self.price,
           'desciption' : self.desciption,
           'date'       : self.date,
           'currency'   : self.currency,
           'x509'       : self.x509,
           'signature'  : self.signature

       }
class Contract(db.Model):      
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(200))
    IV = db.Column(db.String(16))
    data = db.Column(db.Text())
    active = db.Column(db.Boolean, default=False)
    marketplace_id = db.Column(db.Integer, db.ForeignKey('marketplace.id'))
#     state = db.Column(db.Enum(*STATES),default="OPEN")
    data = db.relationship('Dataflow', backref='contract',
                                lazy='dynamic',cascade="all, delete-orphan")
    @property
    def to_json(self):
        return {
           'id'        : self.id,
           'key'       : self.key,
           'data'      : self.data,
           'IV'        : self.IV

       }
class Dataflow(db.Model):
    id = db.Column(db.Integer,primary_key=True)
    AccuData = db.Column(db.Text())
    EncData = db.Column(db.Text())
    OpenData = db.Column(db.Text())
    contract_id = db.Column(db.Integer, db.ForeignKey('contract.id'))
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    
    @property
    def to_json(self):
        return {
           'id'         : self.id,
           'AccuData'   : self.AccuData,
           'OpenData'   : self.OpenData,
           'EncData'    : self.EncData,
           'timestamp'  : self.timestamp
       }
#http://127.0.0.1:5000/marketplace
@app.route('/marketplace')
def get_marketplace():
    tmp = Marketplace.query.all()
    if not tmp:
        return jsonify(result="Empty")
    return jsonify(result=[i.to_json for i in tmp if i.state is not "CLOSED"])

@app.route("/add_marketplace",methods=['POST'])
def put_marketplace():
    name =  str(request.form['name'])#request.args.get("name",type=str)
    #firma = str(request.form['firma'])#request.args.get("firma",type=str)
    price = str(request.form['price'])#request.args.get("price",type=int)
    desciption = str(request.form['description'])#request.args.get("description",type=str)
    currency = str(request.form['currency'])#request.args.get("currency",type=str)
    deadline = str(request.form['deadline'])
    x509_cert = str(request.form['x509'])#request.args.get("x509",type=str)
    signature = str(request.form['signature'])#request.args.get("signature",type=str)
    if not check_parameter([id,x509_cert,name,price,desciption,currency,deadline,signature]):
        return jsonify(result="missing Parameter")
    tmp_cert = X509.load_cert_string(x509_cert)
    #check Cert
    if not checkCert(tmp_cert):
        return jsonify(result = "Cert Check Failed")
        # Check Signature
    if not checkSignature(tmp_cert.get_pubkey(), [name,str(price),desciption,currency,deadline], signature):
        return jsonify(result="Signature Check Failed")
    tmp = Marketplace(name=name,price=price,desciption=desciption,currency=currency,x509=x509_cert,signature=signature,deadline=datetime.datetime.fromtimestamp(float(deadline)))
    db.session.add(tmp)
    db.session.commit()
    return jsonify(result= "OK")

@app.route("/revoke_marketplace",methods=['POST'])
def revoke_marketplace():
    id = str(request.form['id'])#request.args.get("id",type=int)
    x509 = str(request.form['x509'])#request.args.get("x509",type=str)
    nonce = str(request.form['nonce'])#request.args.get("nonce",type=str)
    signature = str(request.form['signature'])#request.args.get("signature",type=str)
    if not check_parameter([id,x509,nonce]):
        return jsonify(result="missing Parameter")
    if len(nonce) != 64:
        return jsonify(result="Invalid Nonce")
    tmp_cert = X509.load_cert_string(x509)
    if not checkCert(tmp_cert):
        return jsonify(result="Cert not Valid")
    if not checkSignature(tmp_cert.get_pubkey(),[str(id),nonce], signature):
        return jsonify(result= "Siganture Invalid")
    if X509.load_cert_string(str(Marketplace.query.get(id).x509)).as_pem() != tmp_cert.as_pem():
#         print X509.load_cert_string(str(Marketplace.query.get(id).x509)).as_text()
#         print tmp_cert.as_text()
        print "Invalid Organisation"
        return "Invalid Organisation"
    
    db.session.delete(Marketplace.query.get(id))
    db.session.commit()
    return jsonify(result="OK")

@app.route("/put_offer",methods=['POST'])
def marketplace_put_offer():
    id = str(request.form['id'])#request.args.get("id",type=int)
    encypted_data = str(request.form['data'])#request.args.get("data",type=str)
    key = str(request.form['key'])#request.args.get("key",type=str)
    IV = str(request.form['IV'])#request.args.get("IV",type=str)
    signature = str(request.form['signature'])#request.args.get("signature",type=str)
    x509 = str(request.form['x509'])#request.args.get("x509",type=str)
    if not check_parameter([str(id),x509,key,IV,encypted_data]):
        return jsonify(result="missing Parameter")
    tmp_cert = X509.load_cert_string(x509)
    if not checkCert(tmp_cert):
        return jsonify(result="Cert not Valid")
    
    if not checkSignature(tmp_cert.get_pubkey(),[str(id),IV,key,encypted_data], signature):#,encypted_data
        return jsonify(result= "Siganture Invalid")
    mp = Marketplace.query.get(id)
    if not mp:
        return jsonify(result="Offer does not exist")
    if mp.state != "OPEN":
        return jsonify(result="Offer not OPEN")
    tmp_contract = Contract(key=key,data=encypted_data,IV=IV)
    mp.contracts.append(tmp_contract)
    db.session.add(tmp_contract)
    db.session.add(mp)
    db.session.commit()
    return jsonify(result="OK")
@app.route("/get_offer",methods=['POST'])
def Mekretplace_get_offers():
    id = str(request.form['id'])#request.args.get("id",type=int)
    timestamp = str(request.form['timestamp'])#request.args.get("timestamp",type=str)
    x509 = str(request.form['x509'])#request.args.get("x509",type=str)
    signature = str(request.form['signature'])#request.args.get("signature",type=str)
    if not check_parameter([str(id),x509,timestamp,signature]):
        return jsonify(result="missing Parameter")
    tmp_cert = X509.load_cert_string(x509)
    if not checkCert(tmp_cert):
        return jsonify(result="Cert not Valid")
    if not checkSignature(tmp_cert.get_pubkey(),[str(id),timestamp], signature):#,encypted_data
        return jsonify(result= "Siganture Invalid")
    
    mp = Marketplace.query.get(id)

    if not mp:
        return jsonify(result="ID doesn't exist")
    if X509.load_cert_string(str(mp.x509)).as_pem() != tmp_cert.as_pem():
#         print X509.load_cert_string(str(Marketplace.query.get(id).x509)).as_text()
#         print tmp_cert.as_text()
        print "Not your Marketplace"
        return jsonify(result="Not your Marketplace")    
    return jsonify(result=[i.to_json for i in mp.contracts])
@app.route("/accept_offer",methods=['POST'])
def Marketplace_accept_offer():
    id = str(request.form['id'])
    nonce = str(request.form['nonce'])
    timestamp = str(request.form['timestamp'])
    x509 = str(request.form['x509'])
    signature = str(request.form['signature'])

    if not check_parameter([str(id),x509,nonce,timestamp,signature]):
        return jsonify(result="missing Parameter")
    
    tmp_cert = X509.load_cert_string(x509)
    if not checkCert(tmp_cert):
        return jsonify(result="Cert not Valid")
    
    if not checkSignature(tmp_cert.get_pubkey(),[str(id),nonce,timestamp], signature):#,encypted_data
        return jsonify(result= "Siganture Invalid")
    
    c = Contract.query.get(id)
    if not c:
        return jsonify(result="Contract Offer does not exist")
    mp = Marketplace.query.get(c.marketplace_id)
    if X509.load_cert_string(str(mp.x509)).as_pem() != tmp_cert.as_pem():
        return jsonify(result="Not your marketplace")
    
    c.active = True
    mp.state="ACTIVE"
    
    db.session.add(c)
    db.session.add(mp)
    db.session.commit()
    
    return jsonify(result="OK")
@app.route("/data_put",methods=['POST'])
def dataFlow_put():

    id = str(request.form['id'])
    data = str(request.form['data'])
    IV = str(request.form['IV'])
    key = str(request.form['key'])
    timestamp =  str(request.form['data'])
    signature = str(request.form['signature'])
    x509 = str(request.form['x509'])
    if not check_parameter([str(id),x509,signature,data,timestamp,IV,key]):
        return jsonify(result="missing Parameter")
    if int(timestamp) + 10 < time.time():
        return jsonify(result="Old data")
    tmp_cert = X509.load_cert_string(x509)
    if not checkCert(tmp_cert):
        return jsonify(result="Cert not Valid") 
    if not checkSignature(tmp_cert.get_pubkey(),[id,data,IV,key,timestamp], signature):#,encypted_data
        return jsonify(result= "Siganture Invalid")
    con = Contract.querry.get(id)
    if not con:
        return jsonify(result="Unkown ID")
    jobj = json.loads(data)
    dataflow = Dataflow(AccuData=jobj['AccuData'],EncData=jobj['EncData'],OpenData=jobj['OpenData'])
    con.data.append(dataflow)
    db.session.add(con)
    db.session.add(dataflow)
    db.session.commit()
    # TODO Check ob gleiche fimra wie vertrag
    return jsonify(result ="OK")
def dataFlow_accu_get():
    id = str(request.form['id'])
    timestamp =  str(request.form['data'])
    signature = str(request.form['signature'])
    raw = str(request.form['signature'])
    x509 = str(request.form['x509'])
    if not check_parameter([str(id),x509,signature,timestamp]):
        return jsonify(result="missing Parameter")
    if int(timestamp) + 10 < time.time():
        return jsonify(result="Old data")
    tmp_cert = X509.load_cert_string(x509)
    if not checkCert(tmp_cert):
        return jsonify(result="Cert not Valid") 
    if not checkSignature(tmp_cert.get_pubkey(),[id,timestamp], signature):#,encypted_data
        return jsonify(result= "Siganture Invalid")
    
    c = Contract.query.get(id)
    if raw == "1":
        return jsonify(result=[i.to_json for i in c.data_accu ])
    #TODO return accu data
    return jsonify(result = "OK, not implemented, use raw:1 for now")
def validate_date():
    MPs = Marketplace.query.all()
    for mp in MPs:
        if int(mp.deadline.strftime("%s")) < int(time.time()) and mp.state is not "ACTIVE":
            mp.state="CLOSED"
            db.session.add(mp)
    db.session.commit()
def checkSignature(pk,args,signature):
    if not isinstance(pk,EVP.PKey):
        print "Not instace of PublicKey"
        return False
    pk.verify_init()
    [pk.verify_update(a) for a in args]
    return pk.verify_final(base64.b64decode(signature))
    
def checkCert(cert):
    if not isinstance(cert, X509.X509):
        print "Not instance of Cert"
        return False
    if not cert.verify(CApk):
        print "Cert Verify failed"
        return False
    return True
def check_parameter(args):
    for a in args:
        if not a:
            return False
    return True