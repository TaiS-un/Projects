import secrets
import binascii
from hashlib import sha256
from gmssl import sm3, func
import time
import functools

# SM2椭圆曲线参数
ELLIPTIC_CURVE_A = 0x787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498
ELLIPTIC_CURVE_B = 0x63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A
PRIME_MODULUS = 0x8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3
ORDER_N = 0x8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7
BASE_POINT_X = 0x421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D
BASE_POINT_Y = 0x0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2
BASE_POINT = (BASE_POINT_X, BASE_POINT_Y)
SM3_HASH_SIZE = 32

# 缓存字典
MODULAR_INVERSE_CACHE = {}
POINT_ADDITION_CACHE = {}
USER_HASH_CACHE = {}


def secure_bytes_equal(a: bytes, b: bytes) -> bool:
    """常量时间比较两个字节串"""
    if len(a) != len(b):
        return False

    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0


def modular_inverse(value, modulus):
    """使用扩展欧几里得算法计算模逆元"""
    cache_key = (value, modulus)
    if cache_key in MODULAR_INVERSE_CACHE:
        return MODULAR_INVERSE_CACHE[cache_key]

    if value == 0:
        return 0

    lm, hm = 1, 0
    low, high = value % modulus, modulus

    while low > 1:
        ratio = high // low
        next_m, next_h = hm - lm * ratio, high - low * ratio
        lm, low, hm, high = next_m, next_h, lm, low

    result = lm % modulus
    MODULAR_INVERSE_CACHE[cache_key] = result
    return result


def sm2_point_addition(pt1, pt2):
    """SM2椭圆曲线上的点加法"""
    cache_key = (pt1, pt2)
    if cache_key in POINT_ADDITION_CACHE:
        return POINT_ADDITION_CACHE[cache_key]

    if pt1 == (0, 0):
        return pt2
    if pt2 == (0, 0):
        return pt1

    x1, y1 = pt1
    x2, y2 = pt2

    if x1 == x2:
        if y1 == y2:
            slope = (3 * x1 * x1 + ELLIPTIC_CURVE_A) * modular_inverse(2 * y1, PRIME_MODULUS)
        else:
            return (0, 0)
    else:
        slope = (y2 - y1) * modular_inverse(x2 - x1, PRIME_MODULUS)

    slope %= PRIME_MODULUS
    x3 = (slope * slope - x1 - x2) % PRIME_MODULUS
    y3 = (slope * (x1 - x3) - y1) % PRIME_MODULUS

    result = (x3, y3)
    POINT_ADDITION_CACHE[cache_key] = result
    return result


def sm2_scalar_multiplication(scalar, point):
    """SM2椭圆曲线上的标量乘法"""
    if not 0 < scalar < ORDER_N:
        raise ValueError("无效的标量")

    result = (0, 0)
    current_point = point

    while scalar:
        if scalar & 1:
            result = sm2_point_addition(result, current_point)
        current_point = sm2_point_addition(current_point, current_point)
        scalar >>= 1

    return result


def compute_user_hash(user_id, public_key_x, public_key_y):
    """计算用户标识哈希值 (ZA)"""
    cache_key = (user_id, public_key_x, public_key_y)
    if cache_key in USER_HASH_CACHE:
        return USER_HASH_CACHE[cache_key]

    id_bitlen = len(user_id.encode('utf-8')) * 8

    components = [
        id_bitlen.to_bytes(2, 'big'),
        user_id.encode('utf-8'),
        ELLIPTIC_CURVE_A.to_bytes(32, 'big'),
        ELLIPTIC_CURVE_B.to_bytes(32, 'big'),
        BASE_POINT_X.to_bytes(32, 'big'),
        BASE_POINT_Y.to_bytes(32, 'big'),
        public_key_x.to_bytes(32, 'big'),
        public_key_y.to_bytes(32, 'big')
    ]
    data_to_hash = b''.join(components)

    result = sm3.sm3_hash(func.bytes_to_list(data_to_hash))
    USER_HASH_CACHE[cache_key] = result
    return result


def generate_keypair():
    """生成SM2密钥对"""
    private_key = secrets.randbelow(ORDER_N - 1) + 1
    public_key = sm2_scalar_multiplication(private_key, BASE_POINT)
    return private_key, public_key


def sign_message(private_key, message, user_id, public_key, k_value=None):
    """生成SM2签名，允许指定k值用于POC验证"""
    za_bytes = bytes.fromhex(compute_user_hash(user_id, public_key[0], public_key[1]))
    data_for_hash = za_bytes + message.encode('utf-8')

    hash_result = sm3.sm3_hash(func.bytes_to_list(data_for_hash))
    e_value = int(hash_result, 16)

    # POC验证允许传入 k_value，否则随机生成
    if k_value is None:
        k_value = secrets.randbelow(ORDER_N - 1) + 1

    temp_point = sm2_scalar_multiplication(k_value, BASE_POINT)
    x_k = temp_point[0]

    r_value = (e_value + x_k) % ORDER_N
    if r_value == 0 or r_value + k_value == ORDER_N:
        return None

    inverse_val = modular_inverse(1 + private_key, ORDER_N)
    s_value = (inverse_val * (k_value - r_value * private_key)) % ORDER_N

    return (r_value, s_value)


def ecdsa_sign_for_poc(private_key, message, k_value=None):
    """ECDSA签名（使用相同的SM2参数），用于POC验证"""
    msg_bytes = message.encode('utf-8')
    hash_output = sha256(msg_bytes).digest()
    e_value = int.from_bytes(hash_output, 'big') % ORDER_N

    if k_value is None:
        k_value = secrets.randbelow(ORDER_N - 1) + 1

    temp_point = sm2_scalar_multiplication(k_value, BASE_POINT)
    r_value = temp_point[0] % ORDER_N
    if r_value == 0:
        return None

    s_value = modular_inverse(k_value, ORDER_N) * (e_value + private_key * r_value) % ORDER_N
    if s_value == 0:
        return None

    return (r_value, s_value)


class SM2_Misuse_Verifier:
    """封装SM2签名误用场景的POC验证"""

    def __init__(self):
        pass

    def verify_leaking_k_attack(self):
        """POC验证：随机数 k 泄露导致私钥泄露"""
        print("\n***** POC验证：随机数k泄露导致私钥泄露 *****")

        priv_key, pub_key = generate_keypair()
        user_id = "test_user"
        print(f"原始私钥: {hex(priv_key)}")

        msg = "测试消息"
        k_value = secrets.randbelow(ORDER_N - 1) + 1
        signature = sign_message(priv_key, msg, user_id, pub_key, k_value)

        if signature is None:
            print("错误：签名失败，请重试")
            return

        r, s = signature

        # 恢复私钥公式: dA = (k - s) * (s + r)^-1 mod n
        denominator = (s + r) % ORDER_N
        if denominator == 0:
            print("错误：分母为零，无法恢复私钥")
            return

        inv_denom = modular_inverse(denominator, ORDER_N)
        recovered_private_key = ((k_value - s) * inv_denom) % ORDER_N

        print(f"使用的随机数k: {hex(k_value)}")
        print(f"恢复的私钥: {hex(recovered_private_key)}")
        print(f"恢复结果: {priv_key == recovered_private_key}")

    def verify_same_user_reused_k(self):
        """POC验证：同一用户重复使用 k 导致私钥泄露"""
        print("\n***** POC验证：同一用户重复使用k导致私钥泄露 *****")

        priv_key, pub_key = generate_keypair()
        user_id = "test_user"
        print(f"原始私钥: {hex(priv_key)}")

        k_value = secrets.randbelow(ORDER_N - 1) + 1
        msg1 = "消息1"
        msg2 = "消息2"

        sig1 = sign_message(priv_key, msg1, user_id, pub_key, k_value)
        sig2 = sign_message(priv_key, msg2, user_id, pub_key, k_value)

        r1, s1 = sig1
        r2, s2 = sig2

        # 恢复私钥公式: dA = (s2-s1) * (s1-s2+r1-r2)^-1 mod n
        numerator = (s2 - s1) % ORDER_N
        denominator = (s1 - s2 + r1 - r2) % ORDER_N

        if denominator == 0:
            print("错误：分母为零，无法恢复私钥")
            return

        inv_denom = modular_inverse(denominator, ORDER_N)
        recovered_private_key = (numerator * inv_denom) % ORDER_N

        print(f"恢复的私钥: {hex(recovered_private_key)}")
        print(f"恢复结果: {priv_key == recovered_private_key}")

    def verify_different_users_same_k(self):
        """POC验证：不同用户使用相同的 k 导致私钥泄露"""
        print("\n***** POC验证：不同用户使用相同的k导致私钥泄露 *****")

        # 用户A
        priv_A, pub_A = generate_keypair()
        user_id_A = "userA"
        print(f"用户A原始私钥: {hex(priv_A)}")

        # 用户B
        priv_B, pub_B = generate_keypair()
        user_id_B = "userB"
        print(f"用户B原始私钥: {hex(priv_B)}")

        k_value = secrets.randbelow(ORDER_N - 1) + 1

        sig_A = sign_message(priv_A, "AAA", user_id_A, pub_A, k_value)
        sig_B = sign_message(priv_B, "BBB", user_id_B, pub_B, k_value)

        rA, sA = sig_A
        rB, sB = sig_B

        # 计算用户A的k值 (攻击者假设已知dA)
        # k = sA*(1+dA) + rA*dA mod n
        k_recovered = (sA * (1 + priv_A) + rA * priv_A) % ORDER_N

        # 恢复用户B的私钥
        # dB = (k - sB) * (sB + rB)^-1 mod n
        denominator = (sB + rB) % ORDER_N
        if denominator == 0:
            print("错误：分母为零，无法恢复私钥")
            return

        inv_denom = modular_inverse(denominator, ORDER_N)
        recovered_private_key_B = ((k_recovered - sB) * inv_denom) % ORDER_N

        print(f"恢复的用户B私钥: {hex(recovered_private_key_B)}")
        print(f"恢复结果: {priv_B == recovered_private_key_B}")

    def verify_sm2_ecdsa_k_misuse(self):
        """POC验证：相同私钥和 k 在SM2和ECDSA中签名导致私钥泄露"""
        print("\n***** POC验证：SM2与ECDSA混合签名导致私钥泄露 *****")

        priv_key, pub_key = generate_keypair()
        user_id = "test_user"
        print(f"原始私钥: {hex(priv_key)}")

        k_value = secrets.randbelow(ORDER_N - 1) + 1

        ecdsa_message = "ECDSA消息"
        ecdsa_sig = ecdsa_sign_for_poc(priv_key, ecdsa_message, k_value)
        r1, s1 = ecdsa_sig

        ecdsa_msg_hash = sha256(ecdsa_message.encode('utf-8')).digest()
        e1 = int.from_bytes(ecdsa_msg_hash, 'big') % ORDER_N

        sm2_message = "SM2消息"
        sm2_sig = sign_message(priv_key, sm2_message, user_id, pub_key, k_value)
        r2, s2 = sm2_sig

        # 恢复私钥公式: d = (s1*s2 - e1) * (r1 - s1*s2 - s1*r2)^-1 mod n
        numerator = (s1 * s2 - e1) % ORDER_N
        denominator = (r1 - s1 * s2 - s1 * r2) % ORDER_N

        if denominator == 0:
            print("错误：分母为零，无法恢复私钥")
            return

        inv_denom = modular_inverse(denominator, ORDER_N)
        recovered_private_key = (numerator * inv_denom) % ORDER_N

        print(f"恢复的私钥: {hex(recovered_private_key)}")
        print(f"恢复结果: {priv_key == recovered_private_key}")


def run_all_poc_tests():
    """主函数，运行所有POC验证"""
    verifier = SM2_Misuse_Verifier()
    verifier.verify_leaking_k_attack()
    verifier.verify_same_user_reused_k()
    verifier.verify_different_users_same_k()
    verifier.verify_sm2_ecdsa_k_misuse()


if __name__ == "__main__":
    run_all_poc_tests()