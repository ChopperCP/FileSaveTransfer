# import gmpy2
import random
from tools import *


class EllipticCurve:
    def __init__(self, a, b, p, G, n):
        # 有限域上的椭圆曲线方程：y^2 mod p = (x^3+ax+b) mod p
        self.a = a
        self.b = b
        self.p = p
        self.G = G  # 生成元,二元组
        self.n = n  # 生成元的阶

    def is_on_curve(self, point):
        # 判断点是否满足曲线方程
        x, y = point
        lhs = (y*y) % self.p
        rhs = (x**3+self.a*x+self.b) % self.p
        if lhs == rhs:
            return True
        return False

    def invert(self, point):
        # 求点的加法逆元
        return (point[0], -point[1] % self.p)

    def add(self, p1, p2):
        # 相加运算
        # p1 p2 是点，二元素元组/列表
        # 注：O=(0,0)是无穷远点，也是加法单位元

        if p1 is None:
            # 0 + p2 = p2
            return p2
        if p2 is None:
            # p1 + 0 = p1
            return p1

        # 相加的点不在曲线上
        if(self.is_on_curve(p1) == False or self.is_on_curve(p2) == False):
            return (0, 0)

        # p+(-p)=(0,0)
        if(p1[0] == p2[0] and p1[1] == -p2[1]):
            return (0, 0)

        l = 0  # lamda
        # 将类型统一为元组
        if(tuple(p1) == tuple(p2)):
            l = ((3*p1[0]*p1[0]+self.a)*invert(2*p1[1], self.p)) % self.p
        else:
            fenzi = p2[1]-p1[1]
            fenmu = p2[0]-p1[0]
            l = (fenzi*invert(fenmu, self.p)) % self.p

        x = ((l*l)-p1[0]-p2[0]) % self.p
        y = (l*(p1[0]-x)-p1[1]) % self.p

        return (x, y)

    def mult(self, k, point):
        # 数乘运算
        assert self.is_on_curve(point)

        if k < 0:
            # k * point = -k * (-point)
            return self.mult(-k, self.invert(point))

        result = None
        addend = point

        while k:
            if k & 1:
                # Add.
                result = self.add(result, addend)

            # Double.
            addend = self.add(addend, addend)

            k >>= 1

        assert self.is_on_curve(result)
        return result

    def get_private_key(self):
        # 随机产生私钥
        return random.randint(1, self.n)

    def get_public_key(self, pri):
        # pri是私钥，数字
        if (pri <= self.n):
            return self.mult(pri, self.G)

    def encrypt(self, plain: bytes, pub):
        # ElGamal 密码体制
        def insert_plain(plain):
            # 将明文嵌入到椭圆曲线上的点，得到曲线上的一个点
            k = 32  # 向左移5位
            for i in range(0, k):
                x = bytes2int(plain) << 5+i
                # 求解 y^2==x^3+a*x+b 中的y
                rhs = (x ** 3+self.a*x+self.b) % self.p
                # p是奇素数，则p是平方剩余<=>(x^3+a*x+b)^((p-1)/2)==1 mod p
                if pow(rhs, (self.p-1) >> 1, self.p) == 1:
                    if (self.p % 4 == 3):
                        # p==4n+3的形式
                        y = pow(rhs, (self.p+1) >> 2, self.p)
                        return (x, y)
                    else:
                        return(x, get_iroot(x, self.p)[0])  # y取其中一个即可

        Pm = insert_plain(plain)  # 嵌入后的点
        r = random.randint(1, self.n)
        # 密文=(k*G,Pm+k*pub)
        return (self.mult(r, self.G), self.add(Pm, self.mult(r, pub)))

    def decrypt(self, cipher, pri):
        # ElGamal 密码体制
        def uninsert_plain(Pm):
            # 将明文提取出来
            x, y = Pm
            k = 32  # 向右移5位
            plain = x >> 6  # don't know why, but it works!
            return int2bytes(plain)

        # 密文=(k*G,Pm+k*pub)
        # Pm=Pm+k*pub-pri*k*G=Pm+k*pri*G-pri*k*G
        Pm = self.add(cipher[1],
                      self.invert(self.mult(pri, cipher[0])))  # 嵌入后的点
        return uninsert_plain(Pm)

    def get_signature(self, plain_hash: bytes, pri):
        # ECDSA 椭圆曲线数字签名算法
        r = random.randint(1, self.n)
        s = (r-bytes2int(plain_hash)*pri) % self.p
        if s == 0:
            # 如果s为0，重新计算
            return self.get_signature(plain_hash, pri)
        return (r, s)

    def is_valid_signature(self, plain_hash: bytes, signature, pub):
        # ECDSA 椭圆曲线数字签名算法
        r, s = signature
        if self.add(self.mult(s, self.G), self.mult(bytes2int(plain_hash), pub)):
            return True
        return False
