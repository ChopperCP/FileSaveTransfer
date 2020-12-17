from aes128 import aes_encrypt, aes_decrypt
from elliptic_curve import *
from sha1 import *
import binascii


def print_status(status, text):
    if status == '+':
        text = '  '+text
    print("[{}] {}".format(status, text))


# 生成Hash
message = input("Please input the message you want to send: ")
print_status('*', "Using SHA1 to generate hash value...")
message_hash = sha1(message.encode('utf8'))
print_status("+", "Hash generated: {}".format(message_hash))
print_status(
    "+", "Hex form: {}".format(binascii.b2a_hex(sha1(message_hash)).decode('utf8')))


# 椭圆曲线签名Hash值
print_status('*', "Using ECDSA to create a signature...")
print_status(
    '*', "  I am using ecp256k1 as the curve. Here are the parameters: (https://www.secg.org/sec2-v2.pdf)")
# ecp256k1 https://www.secg.org/sec2-v2.pdf
a = 0
b = 7
p = 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F'
Gx = '79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798'
Gy = '483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8'
n = 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141'
p, Gx, Gy, n = [int(num, 16) for num in [p, Gx, Gy, n]]
print('''
    a = {}
    b = {}
    p = {}
    G = ({},{})
    n = {}
'''.format(a, b, p, Gx, Gy, n)
      )

ec = EllipticCurve(a, b, p, (Gx, Gy), n)
ec_pri = ec.get_private_key()
print_status('+', '  Private key generated: {}'.format(ec_pri))
ec_pub = ec.get_public_key(ec_pri)
print_status('+', '  Public key generated: {}'.format(ec_pub))

signature = ec.get_signature(message_hash, ec_pri)
print_status('+', 'Signature generated: {}'.format(signature))


# 串接明文和签名(打包)
package = '{}|{},{}'.format(message, *signature)
print_status(
    '+', "Concatenated message and signature (package): {}".format(package))


# 对称加密package
print_status('*', 'Using AES128 to encrypt the package...')
aes_secret = input(
    "  Please input your secret (Not the key to AES128, Used to generate the key, Any length): ")
encrypted_package = aes_encrypt(aes_secret, package)
print_status('+', 'Encrypted package: {}'.format(encrypted_package))


# 传输
print_status('*', 'Transmitting the encrypted package...')
print_status('+', 'Bleep Bleep Bloop Bloop...')
print_status('+', '  Local->Remote')


# 对称解密package
print_status('*', 'Using AES128 to decrypt the package...')
print_status('!', "Your secret is '{}', remember?".format(aes_secret))
decrypted_package = aes_decrypt(aes_secret, encrypted_package).decode('utf8')
print_status('+', 'Decrypted package: {}'.format(decrypted_package))


# 将明文和签名分开(解包)
print_status('*', 'Spliting message and signature...')
decrypted_message, decrypted_signature = decrypted_package.split('|')
decrypted_signature = tuple((int(x) for x in decrypted_signature.split(',')))
print_status('+', 'Message: {}'.format(decrypted_message))
print_status('+', 'Signature: {}'.format(decrypted_signature))


# 检查签名是否有效
print_status('*', "Checking whether the signature is valid")
print_status(
    '!', "Your Elliptic curve public key is: {}, remember?".format(ec_pub))
decrypted_message_hash = sha1(decrypted_message.encode('utf8'))
print_status('+', "Is the signature valid? {}".format(
    ec.is_valid_signature(decrypted_message_hash, decrypted_signature, ec_pub)))
