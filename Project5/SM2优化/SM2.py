import secrets
import binascii
from gmssl import sm3, func
import time

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


def sign_message(private_key, message, user_id, public_key):
    """生成SM2签名"""
    # compute_user_hash 返回的是一个十六进制字符串，需要转换为字节串
    za = bytes.fromhex(compute_user_hash(user_id, public_key[0], public_key[1]))

    # 消息也需要是字节串
    data_for_hash = za + message.encode('utf-8')

    hash_result = sm3.sm3_hash(func.bytes_to_list(data_for_hash))
    e_value = int(hash_result, 16)

    while True:
        k_val = secrets.randbelow(ORDER_N - 1) + 1

        temp_point = sm2_scalar_multiplication(k_val, BASE_POINT)
        x_k = temp_point[0]

        r_value = (e_value + x_k) % ORDER_N
        if r_value == 0 or r_value + k_val == ORDER_N:
            continue

        inverse_val = modular_inverse(1 + private_key, ORDER_N)
        s_value = (inverse_val * (k_val - r_value * private_key)) % ORDER_N
        if s_value != 0:
            return (r_value, s_value)


def verify_signature(public_key, message, user_id, signature):
    """验证SM2签名"""
    r_val, s_val = signature

    if not (0 < r_val < ORDER_N and 0 < s_val < ORDER_N):
        return False

    # compute_user_hash 返回的是一个十六进制字符串，需要转换为字节串
    za = bytes.fromhex(compute_user_hash(user_id, public_key[0], public_key[1]))

    # 消息也需要是字节串
    data_for_hash = za + message.encode('utf-8')

    hash_result = sm3.sm3_hash(func.bytes_to_list(data_for_hash))
    e_value = int(hash_result, 16)

    t_val = (r_val + s_val) % ORDER_N

    point_s_G = sm2_scalar_multiplication(s_val, BASE_POINT)
    point_t_P = sm2_scalar_multiplication(t_val, public_key)

    result_point = sm2_point_addition(point_s_G, point_t_P)

    calculated_R = (e_value + result_point[0]) % ORDER_N

    return secure_bytes_equal(r_val.to_bytes(32, 'big'), calculated_R.to_bytes(32, 'big'))


def key_derivation_function(z: bytes, klen: int) -> bytes:
    """密钥派生函数 (KDF)"""
    counter = 1
    derived_key = b''
    klen_bytes = (klen + 7) // 8

    while len(derived_key) < klen_bytes:
        input_data = z + counter.to_bytes(4, 'big')
        hash_output = bytes.fromhex(sm3.sm3_hash(func.bytes_to_list(input_data)))
        derived_key += hash_output
        counter += 1

    return derived_key[:klen_bytes]


def sm2_encrypt(public_key, plaintext: bytes) -> bytes:
    """SM2加密算法"""
    if public_key == (0, 0):
        raise ValueError("公钥无效，不能为无穷远点")

    k_val = secrets.randbelow(ORDER_N - 1) + 1

    c1_point = sm2_scalar_multiplication(k_val, BASE_POINT)
    c1_x, c1_y = c1_point

    k_pb_point = sm2_scalar_multiplication(k_val, public_key)
    x2, y2 = k_pb_point

    x2_bytes = x2.to_bytes(32, 'big')
    y2_bytes = y2.to_bytes(32, 'big')

    kdf_output = key_derivation_function(x2_bytes + y2_bytes, len(plaintext) * 8)

    if all(b == 0 for b in kdf_output):
        raise ValueError("KDF输出全零，需要重新加密")

    c2 = bytes(p ^ t for p, t in zip(plaintext, kdf_output))

    c3_input = x2_bytes + plaintext + y2_bytes
    c3 = bytes.fromhex(sm3.sm3_hash(func.bytes_to_list(c3_input)))

    c1_bytes = c1_x.to_bytes(32, 'big') + c1_y.to_bytes(32, 'big')

    return c1_bytes + c3 + c2


def sm2_decrypt(private_key, ciphertext: bytes) -> bytes:
    """SM2解密算法"""
    min_length = 64 + 32 + 1
    if len(ciphertext) < min_length:
        raise ValueError("密文长度无效")

    c1_bytes = ciphertext[:64]
    c1_x = int.from_bytes(c1_bytes[:32], 'big')
    c1_y = int.from_bytes(c1_bytes[32:64], 'big')
    c1_point = (c1_x, c1_y)

    c3 = ciphertext[64:96]
    c2 = ciphertext[96:]

    x2y2_point = sm2_scalar_multiplication(private_key, c1_point)
    x2, y2 = x2y2_point

    x2_bytes = x2.to_bytes(32, 'big')
    y2_bytes = y2.to_bytes(32, 'big')

    kdf_output = key_derivation_function(x2_bytes + y2_bytes, len(c2) * 8)

    if all(b == 0 for b in kdf_output):
        raise ValueError("KDF输出全零，解密失败")

    decrypted_text = bytes(c ^ k for c, k in zip(c2, kdf_output))

    c3_check_input = x2_bytes + decrypted_text + y2_bytes
    calculated_c3 = bytes.fromhex(sm3.sm3_hash(func.bytes_to_list(c3_check_input)))

    if not secure_bytes_equal(calculated_c3, c3):
        raise ValueError("哈希值校验失败，密文可能被篡改")

    return decrypted_text


def main():
    """演示SM2主要功能"""
    print("--- SM2 密钥生成 ---")
    priv_key, pub_key = generate_keypair()
    print(f"私钥: {hex(priv_key)}")
    print(f"公钥: ({hex(pub_key[0])}, {hex(pub_key[1])})")

    print("\n--- SM2 签名验证 ---")
    message_to_sign = "hello SM2"
    user_id = "user123"
    print(f"待签名消息: '{message_to_sign}'")
    print(f"用户ID: '{user_id}'")

    signature = sign_message(priv_key, message_to_sign, user_id, pub_key)
    print(f"生成的签名: (r={hex(signature[0])}, s={hex(signature[1])})")

    is_valid = verify_signature(pub_key, message_to_sign, user_id, signature)
    print(f"签名验证结果: {'成功' if is_valid else '失败'}")

    print("\n--- SM2 加密解密 ---")
    plaintext_bytes = b"This is a secret message."
    print(f"原始明文: {plaintext_bytes.decode()}")

    try:
        ciphertext = sm2_encrypt(pub_key, plaintext_bytes)
        print(f"加密后的密文 (十六进制): {binascii.hexlify(ciphertext).decode()}")

        decrypted_bytes = sm2_decrypt(priv_key, ciphertext)
        print(f"解密后的明文: {decrypted_bytes.decode()}")

    except ValueError as e:
        print(f"加解密失败: {e}")


if __name__ == "__main__":
    main()