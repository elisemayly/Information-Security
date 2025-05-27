import gmpy2
from gmpy2 import mpz, powmod, invert, next_prime, random_state, mpz_urandomb

# 生成2048位素数
def generate_prime(bits, rand):
    while True:
        p = mpz_urandomb(rand, bits)
        p = next_prime(p)
        if p.bit_length() == bits:
            return p

def generate_rsa_keypair(bits=2048):
    rand = random_state()
    half_bits = bits // 2
    p = generate_prime(half_bits, rand)
    q = generate_prime(half_bits, rand)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = mpz(65537)
    d = invert(e, phi)
    return (n, e, d)

def rsa_encrypt(m, e, n):
    return powmod(m, e, n)

def rsa_decrypt(c, d, n):
    return powmod(c, d, n)

if __name__ == "__main__":
    # 生成密钥对
    print("正在生成2048位RSA密钥对，请稍等...")
    n, e, d = generate_rsa_keypair(2048)
    print("公钥(n, e):")
    print("n =", n)
    print("e =", e)
    print("私钥d:")
    print("d =", d)

    # 明文（16进制字符串）
    hex_plain = "1234567890ABCDEF"
    m = mpz(hex_plain, 16)
    print("明文整数:", m)

    # 加密
    c = rsa_encrypt(m, e, n)
    print("密文:", c)

    # 解密
    m2 = rsa_decrypt(c, d, n)
    print("解密后明文:", m2)
    print("解密后明文（16进制）:", hex(m2))

    # 验证
    assert m == m2
    print("加解密成功！")