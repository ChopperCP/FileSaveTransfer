def invert(k, p):
    # 扩展欧几里得算法求k关于p的逆元
    if k == 0:
        raise ZeroDivisionError('division by zero')

    if k < 0:
        # k ** -1 = p - (-k) ** -1 (mod p)
        return p - invert(-k, p)

    # Extended Euclidean algorithm.
    s, old_s = 0, 1
    t, old_t = 1, 0
    r, old_r = p, k

    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t

    gcd, x, y = old_r, old_s, old_t

    assert gcd == 1
    assert (k * x) % p == 1

    return x % p


def quick_power(a, b, p):
    """
    求快速幂。ret = a^b%p。

    Args:
        a: 底数。大于等于0并且是整数。
        b: 指数。大于等于0并且是整数。
        p: 模数。大于0并且是整数。

    Returns:
        返回结果。

    Raises:
        IOError: 无错误。
    """
    a = a % p
    ans = 1
    while b != 0:
        if b & 1:
            ans = (ans * a) % p
        b >>= 1
        a = (a * a) % p
    return ans


def is_have_iroot(x, p):
    """
        是否有模平方根y*y=x mod p，已知x，p，判断是否存在y

        Args:
            x: 大于0并且小于p的整数。
            p: 质数。

        Returns:
            返回结果，true表示有模平方根；false表示没有模平方根。

        Raises:
            IOError: 无错误。
    """
    ret = quick_power(x, (p - 1) // 2, p)
    if ret == 1:
        return True
    else:
        return False


def get_iroot(x, p):
    """
        求模平方根y*y=x mod p，已知x，p求y

        Args:
            x: 大于0并且小于p的整数。
            p: 质数。

        Returns:
            返回结果y。

        Raises:
            IOError: 无错误。
    """
    t = 0
    # p-1=(2^t)*s //s是奇数
    s = p - 1
    while s % 2 == 0:
        s = s // 2
        t = t + 1
    if t == 1:
        ret = quick_power(x, (s + 1) // 2, p)
        return ret, p - ret
    elif t >= 2:
        x_ = quick_power(x, p - 2, p)
        n = 1
        while is_have_iroot(n, p):
            n = n + 1
        b = quick_power(n, s, p)
        ret = quick_power(x, (s + 1) // 2, p)
        t_ = 0
        while t - 1 > 0:
            if quick_power(x_ * ret * ret, 2 ** (t - 2), p) == 1:
                pass
            else:
                ret = ret * (b ** (2 ** t_)) % p
            t = t - 1
            t_ = t_ + 1
        return ret, p - ret
    else:
        raise Exception()
