from sqlalchemy import Integer, Column, create_engine, ForeignKey, String, DateTime, Enum, Text, Boolean
from sqlalchemy.orm import relationship, joinedload, subqueryload, Session, sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from json import loads, dumps
from collections import defaultdict
from paillier.paillier import *
from Crypto.PublicKey import RSA
from M2Crypto import X509
from PublicCloud import STATES
import pprint
import datetime

Base = declarative_base()

class Marketplace(Base):
    __tablename__ = 'marketplace'
    id = Column(Integer, primary_key=True)
    name = Column(String(128))
    #firma = db.Column(db.String(128))
    price = Column(Integer)
    desciption = Column(String(200))
    date = Column(DateTime, default=datetime.datetime.utcnow)
    deadline =  Column(DateTime, default=datetime.datetime.utcnow)
    currency = Column(String(3),default="EUR")
    x509 = Column(String(1000))
    signature = Column(String(1000))
    state = Column(Enum(*STATES),default="OPEN")
    contracts = relationship('Contract', backref='marketplace',
                                lazy='dynamic',cascade="all, delete-orphan")
class Contract(Base):
    __tablename__ = 'contract'      
    id = Column(Integer, primary_key=True)
    key = Column(String(200))
    IV = Column(String(16))
    data = Column(Text())
    active = Column(Boolean, default=False)
    marketplace_id = Column(Integer, ForeignKey('marketplace.id'))
    state = Column(Enum(*STATES),default="OPEN")
    flowdata = relationship('Dataflow', backref='contract',
                                lazy='dynamic',cascade="all, delete-orphan")
    accudata =  relationship("AccuData", uselist=False, backref="contract")
    
class AccuData(Base):
    __tablename__ = 'accudata'
    id = Column(Integer,primary_key=True)
    data = Column(Text())
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    parent_id = Column(Integer, ForeignKey('contract.id'))
    
class Dataflow(Base):
    __tablename__ = 'dataflow'
    id = Column(Integer,primary_key=True)
    iv = Column(Text())
    key = Column(Text())
    data = Column(Text())
    contract_id = Column(Integer, ForeignKey('contract.id'))
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)

def doCron():
    engine = create_engine('sqlite:///test.db')
    session = sessionmaker()
    session.configure(bind=engine)
    #Base.metadata.create_all(engine)


    s = session()
    s._model_changes = {}
    for mp in s.query(Marketplace).all():
        if "ACTIVE" not in mp.state:
            continue
        n=  RSA.importKey(X509.load_cert_string(str(mp.x509)).get_pubkey().get_rsa().as_pem()).key.n
        pubKey = PublicKey(n)
        for con in mp.contracts:
            if not con.accudata:
                accu_data = defaultdict(lambda: 0)
            else:
                accu_data = loads(con.accudata.data)
            for data in con.flowdata:
                for key , value in loads(data.data)['AccuData'].iteritems():
                    #print key , value
                    if accu_data[key]:
                        accu_data[key] = e_add(pubKey, accu_data[key], value)
                    else:
                        accu_data[key] = value
            data_string = dumps(accu_data)
            #pprint.pprint(accu_data)
            if con.accudata:
                con.accudata.data = data_string
                con.accudata.timestamp = datetime.datetime.utcnow()
            else:
                con.accudata = AccuData(data=data_string)
            s.add(con)
            s.commit()
if __name__ == '__main__':
    doCron()
            
    #print s.query(Marketplace).all()[0].id