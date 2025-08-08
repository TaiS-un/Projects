import random
import hashlib
from typing import List, Tuple, Dict
from math import gcd

# --- 1. 密码学原语实现 ---
# 以下是Paillier加密和DDH协议所需的基本数学工具

class Paillier:
    """
    一个简单的 Paillier 加密方案实现。
    """
    def __init__(self, n_bits=1024):
        p = self.generate_prime(n_bits // 2)
        q = self.generate_prime(n_bits // 2)
        
        self.n = p * q
        self.g = self.n + 1
        self.n_squared = self.n * self.n
        
        lmbda = (p - 1) * (q - 1) // gcd(p - 1, q - 1)
        self.mu = self.mod_inverse(lmbda, self.n)
        
        self.public_key = self.n
        self.private_key = (lmbda, self.mu)

    def generate_prime(self, bits):
        while True:
            p = random.getrandbits(bits)
            if p % 2 == 0:
                p += 1
            if self.is_prime(p):
                return p

    def is_prime(self, n, k=128):
        if n == 2 or n == 3:
            return True
        if n <= 1 or n % 2 == 0:
            return False
        
        d = n - 1
        s = 0
        while d % 2 == 0:
            d //= 2
            s += 1
        
        for _ in range(k):
            a = random.randint(2, n - 2)
            x = pow(a, d, n)
            if x == 1 or x == n - 1:
                continue
            for _ in range(s - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True

    def mod_inverse(self, a, m):
        return pow(a, -1, m)

    def encrypt(self, plaintext):
        r = random.randint(1, self.n - 1)
        while gcd(r, self.n) != 1:
            r = random.randint(1, self.n - 1)
        
        return (pow(self.g, plaintext, self.n_squared) * pow(r, self.n, self.n_squared)) % self.n_squared

    def decrypt(self, ciphertext):
        return (self.L(pow(ciphertext, self.private_key[0], self.n_squared)) * self.private_key[1]) % self.n

    def add(self, c1, c2):
        return (c1 * c2) % self.n_squared

    def L(self, u):
        return (u - 1) // self.n

class DDHProtocol:
    """
    DDH协议的群操作和哈希函数。
    这里使用了一个简单的模幂运算群。
    """
    def __init__(self, p_bits=512):
        while True:
            q = self.generate_prime(p_bits)
            p = 2 * q + 1
            if self.is_prime(p):
                self.p = p
                self.q = q
                self.g = random.randint(2, p - 2)
                # 确保g是q阶子群的生成元
                if pow(self.g, self.q, self.p) == 1:
                    break
    
    def generate_prime(self, bits):
        return Paillier().generate_prime(bits)

    def is_prime(self, n):
        return Paillier().is_prime(n)

    def hash_to_group(self, item: str):
        h = int(hashlib.sha256(item.encode()).hexdigest(), 16)
        return pow(self.g, h % self.q, self.p)
    
    def hash_and_exponentiate(self, item: str, exponent: int):
        hashed = self.hash_to_group(item)
        return pow(hashed, exponent, self.p)

# --- 2. 协议实现 (对应 Figure 2) ---

def deployed_pi_sum_protocol(v_set: List[str], w_t_pairs: List[Tuple[str, int]]):
    """
    DDH-based 私有交集求和协议的主函数。
    模拟P1和P2之间的交互。
    """
    print("--- 协议开始 ---")
    
    # 双方共享的设置
    ddh = DDHProtocol()
    
    # --- Setup ---
    # P1 选择私钥
    k1 = random.randint(1, ddh.q - 1)
    
    # P2 选择私钥并生成AHE密钥对
    k2 = random.randint(1, ddh.q - 1)
    ahe = Paillier()
    pk = ahe.public_key
    
    print("Setup: P2生成Paillier密钥对，并将公钥发送给P1。")
    print(f"P1私钥 k1: {k1}")
    print(f"P2私钥 k2: {k2}")

    # --- Round 1 (P1) ---
    print("\n--- 第一轮 (P1) ---")
    p1_hashed_exp = [ddh.hash_and_exponentiate(v, k1) for v in v_set]
    random.shuffle(p1_hashed_exp)
    
    print("P1: 计算 H(vi)^k1 并打乱顺序。发送给P2。")
    
    # --- Round 2 (P2) ---
    print("\n--- 第二轮 (P2) ---")
    
    # Step 1-2: P2 处理 P1 发送来的数据
    p2_hashed_exp_processed = [pow(val, k2, ddh.p) for val in p1_hashed_exp]
    z_set = p2_hashed_exp_processed.copy()
    random.shuffle(z_set)
    
    # Step 3-4: P2 处理自己的数据
    w_processed = []
    for w, t in w_t_pairs:
        hashed_exp_w = ddh.hash_and_exponentiate(w, k2)
        encrypted_t = ahe.encrypt(t)
        w_processed.append((hashed_exp_w, encrypted_t))
    random.shuffle(w_processed)
    
    print("P2: 处理P1的数据得到 H(vi)^k1k2，并打乱顺序。")
    print("P2: 计算 H(wj)^k2 和 AEnc(tj)，并打乱顺序。发送给P1。")
    
    # --- Round 3 (P1) ---
    print("\n--- 第三轮 (P1) ---")
    
    # Step 1: P1 处理 P2 发送来的数据
    processed_w = [(pow(hw, k1, ddh.p), et) for hw, et in w_processed]
    
    # Step 2: 找到交集
    intersection_ciphertexts = []
    intersection_size = 0
    
    processed_w_map = {hw: et for hw, et in processed_w}
    
    for val_z in z_set:
        if val_z in processed_w_map:
            intersection_size += 1
            intersection_ciphertexts.append(processed_w_map[val_z])
            # 为了防止重复匹配，可以从map中移除
            # del processed_w_map[val_z] 
    
    # Step 3: P1 同态求和
    if not intersection_ciphertexts:
        sum_ciphertext = ahe.encrypt(0)
    else:
        sum_ciphertext = intersection_ciphertexts[0]
        for i in range(1, len(intersection_ciphertexts)):
            sum_ciphertext = ahe.add(sum_ciphertext, intersection_ciphertexts[i])
            
    # P1 随机化密文（这里简化为直接发送）
    print(f"P1: 找到交集大小 {intersection_size}。")
    print("P1: 对交集中的密文进行同态求和。")
    
    # --- Output (P2) ---
    print("\n--- 输出 (P2) ---")
    
    # P2 解密得到总和
    final_sum = ahe.decrypt(sum_ciphertext)
    
    print("P2: 接收加密总和，并用私钥解密。")
    print(f"最终结果: 交集大小 = {intersection_size}, 总和 = {final_sum}")
    
    return intersection_size, final_sum


# --- 3. 运行示例 ---
if __name__ == "__main__":
    # P1 的输入
    p1_items = ["userA", "userB", "userC", "userD"]
    # P2 的输入
    p2_items_with_values = [
        ("userA", 100),
        ("userC", 200),
        ("userE", 50),
        ("userF", 75)
    ]
    
    # 预期结果
    # 交集用户: userA, userC
    # 交集大小: 2
    # 总和: 100 + 200 = 300
    
    intersection_size, final_sum = deployed_pi_sum_protocol(p1_items, p2_items_with_values)
    
    print("\n--- 验证结果 ---")
    print(f"预期交集大小: 2")
    print(f"预期总和: 300")
    
    assert intersection_size == 2
    assert final_sum == 300
    print("验证通过！")