from tools import *
from sha1 import *
import binascii

data = b'hello world'
print(binascii.b2a_hex(sha1(data)).decode('utf8'))

pub = (1, 2)
print('{} {}'.format(*pub))
print(str([1, (3, 5)]))
