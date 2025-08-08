from ecpy.curves import Curve, Point
import random

# 使用 secp256k1 曲线，这是比特币所采用的曲线
ecc_curve = Curve.get_curve('secp256k1')
curve_order = ecc_curve.order  # 曲线的阶
base_point = ecc_curve.generator  # 基点

# “中本聪”公钥
satoshi_pub_key = Point(
    0x678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb6,
    0x49f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f,
    ecc_curve
)


def create_forged_signature():
    """
    通过ECDSA验证公式的逆向推导，生成一个伪造的签名。
    这个函数生成一个 (r, s) 签名对，并计算出能通过验证的“假”消息哈希 (e_prime)。
    """
    while True:
        # 随机选择两个大整数作为参数
        u = random.randint(1, curve_order - 1)
        v = random.randint(1, curve_order - 1)

        # 确保 v 不等于 0 (mod n)，避免求逆失败
        if v != 0:
            break

    # 计算签名中的 r 值
    # 这一步是伪造的核心，它利用了验证公式 P = u1*G + u2*Q
    # 我们可以选择 u1 = u*s_prime, u2 = r_prime, Q = pub_key
    # 于是 P = u*s_prime*G + r_prime*pub_key
    # 但我们构造 P = u*G + v*pub_key，然后求出 r_prime
    # 这样，我们就可以通过 r_prime = P.x (mod n) 得到 r_prime
    forged_R = u * base_point + v * satoshi_pub_key
    r_val = forged_R.x % curve_order

    # 计算 s 值
    # 验证公式中 r_prime = (e_prime*w + r_prime*w)*G.x % n, w=s_inv
    # (r_prime*s_inv*r_prime + e_prime*s_inv) * G
    # P = (e_prime*w)*G + (r_prime*w)*Q
    # 我们知道 P = u*G + v*Q
    # 从而 u = e_prime*w (mod n), v = r_prime*w (mod n)
    # 所以 s_inv = v_inv * r_prime (mod n)
    # s = r_prime * v_inv (mod n)
    v_inv = pow(v, curve_order - 2, curve_order)  # 模逆运算
    s_val = (r_val * v_inv) % curve_order

    # 计算与伪造签名匹配的消息哈希
    # 从 u = e_prime*w 推出 e_prime = u*s (mod n)
    # 其中 w = s_inv (mod n)，所以 e_prime = u * s (mod n)
    e_val = (u * s_val) % curve_order

    # 返回伪造的签名和对应的消息哈希
    return (r_val, s_val), e_val


def check_signature(public_key, message_hash, signature):
    """
    执行ECDSA的签名验证过程，检查给定的签名是否有效。
    """
    r, s = signature

    # 检查 r 和 s 的范围是否正确
    if not (1 <= r < curve_order and 1 <= s < curve_order):
        return False

    # 验证过程中的模逆和乘法
    s_inv = pow(s, curve_order - 2, curve_order)
    h_times_s_inv = (message_hash * s_inv) % curve_order
    r_times_s_inv = (r * s_inv) % curve_order

    # 核心的椭圆曲线点运算
    # P = u1 * G + u2 * Q
    # u1 = h * s^-1 (mod n)
    # u2 = r * s^-1 (mod n)
    verification_point = h_times_s_inv * base_point + r_times_s_inv * public_key

    # 验证签名是否通过
    return verification_point.x % curve_order == r


def main_experiment():
    """主程序：执行签名伪造和验证实验"""
    print("--- 中本聪签名伪造实验 ---")

    # 伪造一个签名和对应的消息哈希
    forged_signature_pair, corresponding_hash = create_forged_signature()

    print("\n[结果] 伪造的签名和对应的消息哈希：")
    print(f"r: {hex(forged_signature_pair[0])}")
    print(f"s: {hex(forged_signature_pair[1])}")
    print(f"对应的消息哈希 (e): {hex(corresponding_hash)}")

    # 使用伪造的签名和哈希进行验证
    is_signature_valid = check_signature(satoshi_pub_key, corresponding_hash, forged_signature_pair)

    print("\n[验证] 签名验证结果：")
    print(f"验证状态：{'成功' if is_signature_valid else '失败'}")


if __name__ == "__main__":
    main_experiment()