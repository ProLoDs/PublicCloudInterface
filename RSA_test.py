from Crypto.PublicKey import RSA
from paillier.paillier import *
import time
with open("PublicCloud/keypair","r") as f:
    rsa = RSA.importKey(f.read())
    
print rsa.key.p,"\n", rsa.key.q ,"\n", rsa.key.n
#print rsa.publickey().exportKey()
#print isinstance(rsa, RSA._RSAobj)
priv = PrivateKey(rsa.key.p,rsa.key.q,rsa.key.n)
pub =  PublicKey(rsa.key.n)
#print priv , pub
start = time.time()
x = encrypt(pub, 10)
#print "Time:", time.time() -start
y = encrypt(pub, 22)
#print x,y
z = e_add(pub, x, y)
# print z
# print decrypt(priv, pub, z)