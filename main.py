# from aes import *
from elliptic_curve import *
from sha1 import *

# ecp256k1 https://www.secg.org/sec2-v2.pdf
a = 0
b = 7
p = 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F'
Gx = '79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798'
Gy = '483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8'
n = 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141'
p, Gx, Gy, n = [int(num, 16) for num in [p, Gx, Gy, n]]

ec = EllipticCurve(a, b, p, (Gx, Gy), n)
pri = ec.get_private_key()
pub = ec.get_public_key(pri)

data = b'fasdo23dfdfjoo'
data_hash = sha1(data)

# signature = ec.sign(data_hash, pri)
# print(ec.is_valid_signature(data_hash, signature, pub))

cipher = ec.encrypt(data, pub)
print(cipher)
plain = ec.decrypt(cipher, pri)
print(plain)
