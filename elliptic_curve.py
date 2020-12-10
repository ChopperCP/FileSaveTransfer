# import gmpy2
import random
from tools import *


class Keys:
    def __init__(self, pri, pub):
        self.pri = pri  # 私钥
        self.pub = pub  # 公钥，是点，二元素元组


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
        return (point[0], -point[1])

    def add(self, p1, p2):
        # 相加运算
        # p1 p2 是点，二元素元组/列表
        # 注：O=(0,0)是无穷远点，也是加法单位元

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

    def mult(self, n, p):
        # 数乘运算
        # p 是点，二元素元组
        ans = list(p)  # 元组不可修改，暂时改为列表
        # n*p，做n-1次加法运算
        for _ in range(0, n-1):
            ans = self.add(ans, p)
        return ans
    # 由私钥获取公私钥对

    def get_public_key(self, pri):
        # pri是私钥，数字
        if (pri <= self.n):
            return Keys(pri, self.mult(pri, self.G))

    def pub_encrypt(self, plain: bytes, pub):
        def insert_plain(plain):
            # 将明文嵌入到椭圆曲线上的点，得到曲线上的一个点
            k = 30
            for i in range(0, k):
                x = int(plain, 16)*k+i
                # 求解 y^2==x^3+a*x+b 中的y
                rhs = x ^ 3+self.a*x+self.b
                # p是奇素数，则p是平方剩余<=>(x^3+a*x+b)^((p-1)/2)==1 mod p
                if pow((rhs, self.p-1)/2, self.p) == 1:
                    if (self.p % 4 == 3):
                        # p==4n+3的形式
                        y = pow(rhs, (p+1)/4, self.p)
                        return (x, y)
                    else:
                        return(x, get_iroot(x, self.p)[0])  # y取其中一个即可

        Pm = insert_plain(plain)  # 嵌入后的点
        k = random.randint(1, self.n)
        # 密文=(k*G,Pm+k*pub)
        return (self.mult(k, self.G), self.add(Pm, self.mult(k, pub)))

    def pri_encrypt(self, plain: bytes, pri):
        return self.pub_encrypt(plain, self.get_public_key(pri))
        # TODO 解决公钥加密私钥解密的数字签名问题

    def pri_decrypt(self, cipher, pri):
        def uninsert_plain(Pm):
            # 将明文提取出来
            x, y = Pm
            k = 30
            plain = int(x/k)
            return hex(plain)[2:].encode('utf8')

        Pm = self.add(cipher[1],
                      self.invert(self.mult(pri, cipher[0])))  # 嵌入后的点
        return uninsert_plain(Pm)

    def pub_decrypt(self, cipher, pub):
        # TODO 解决公钥加密私钥解密的数字签名问题

        # ecp256k1
p = 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F'
Gx = '79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798'
Gy = '483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8'
p, Gx, Gy = [int(num, 16) for num in [p, Gx, Gy]]
print(pow(Gy, 2, p) == (pow(Gx, 3, p)+7))
