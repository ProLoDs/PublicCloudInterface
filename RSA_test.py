from Crypto.PublicKey import RSA
from paillier.paillier import *
import time
with open("PublicCloud/ca_keypair","r") as f:
    rsa = RSA.importKey(f.read())
    
#print rsa.key.q
print "key" , len(str(rsa.key.p)) * 8 
priv = PrivateKey(rsa.key.p,rsa.key.q,rsa.key.n)
pub =  PublicKey(rsa.key.n)
#print priv , pub
start = time.time()
x = encrypt(pub, 10)
#print "Time:", time.time() -start
y = encrypt(pub, 22)

z = e_add(pub, x, y)

print decrypt(priv, pub, z)