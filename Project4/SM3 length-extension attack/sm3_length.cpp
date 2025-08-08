#include <iostream>
#include <vector>
#include <string>
#include <cstdint>
#include <iomanip>
#include <chrono>
#include <sstream>

// 循环左移
uint32_t rol(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

// 布尔函数 ff
uint32_t ff(uint32_t x, uint32_t y, uint32_t z, int j) {
    if (j >= 0 && j <= 15) {
        return x ^ y ^ z;
    }
    else {
        return (x & y) | (x & z) | (y & z);
    }
}

// 布尔函数 gg
uint32_t gg(uint32_t x, uint32_t y, uint32_t z, int j) {
    if (j >= 0 && j <= 15) {
        return x ^ y ^ z;
    }
    else {
        return (x & y) | ((~x) & z);
    }
}

// 置换函数 p0
uint32_t p0(uint32_t x) {
    return x ^ rol(x, 9) ^ rol(x, 17);
}

// 置换函数 p1
uint32_t p1(uint32_t x) {
    return x ^ rol(x, 15) ^ rol(x, 23);
}

class sm3 {
public:
    // 计算消息的哈希值
    std::vector<uint32_t> hash(const std::string& message) {
        std::vector<uint8_t> padded_message = padding(message);

        std::vector<uint32_t> h = initial_h;
        for (size_t i = 0; i < padded_message.size(); i += 64) {
            std::vector<uint8_t> block(padded_message.begin() + i, padded_message.begin() + i + 64);
            h = cf(h, block);
        }
        return h;
    }

    // 公开cf函数，用于长度扩展攻击
    std::vector<uint32_t> cf(const std::vector<uint32_t>& h, const std::vector<uint8_t>& block) {
        std::vector<uint32_t> w(68);
        for (int i = 0; i < 16; ++i) {
            w[i] = (static_cast<uint32_t>(block[i * 4]) << 24) |
                (static_cast<uint32_t>(block[i * 4 + 1]) << 16) |
                (static_cast<uint32_t>(block[i * 4 + 2]) << 8) |
                static_cast<uint32_t>(block[i * 4 + 3]);
        }

        for (int i = 16; i < 68; ++i) {
            w[i] = p1(w[i - 16] ^ w[i - 9] ^ rol(w[i - 3], 15)) ^ rol(w[i - 13], 7) ^ w[i - 6];
        }

        std::vector<uint32_t> w_prime(64);
        for (int i = 0; i < 64; ++i) {
            w_prime[i] = w[i] ^ w[i + 4];
        }

        uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
        uint32_t e = h[4], f = h[5], g = h[6], h0 = h[7];

        for (int j = 0; j < 64; ++j) {
            uint32_t t_val = (j <= 15) ? 0x79cc4519 : 0x7a879d8a;
            uint32_t ss1 = rol(rol(a, 12) + e + rol(t_val, j), 7);
            uint32_t ss2 = ss1 ^ rol(a, 12);
            uint32_t tt1 = ff(a, b, c, j) + d + ss2 + w_prime[j];
            uint32_t tt2 = gg(e, f, g, j) + h0 + ss1 + w[j];

            d = c;
            c = rol(b, 9);
            b = a;
            a = tt1;
            h0 = g;
            g = rol(f, 19);
            f = e;
            e = p0(tt2);
        }

        std::vector<uint32_t> result(8);
        result[0] = h[0] ^ a;
        result[1] = h[1] ^ b;
        result[2] = h[2] ^ c;
        result[3] = h[3] ^ d;
        result[4] = h[4] ^ e;
        result[5] = h[5] ^ f;
        result[6] = h[6] ^ g;
        result[7] = h[7] ^ h0;
        return result;
    }

private:
    const std::vector<uint32_t> initial_h = {
        0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
        0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e
    };

    // 填充函数
    std::vector<uint8_t> padding(const std::string& message) {
        size_t len = message.length();
        std::vector<uint8_t> padded_message(message.begin(), message.end());

        padded_message.push_back(0x80);
        while ((padded_message.size() * 8) % 512 != 448) {
            padded_message.push_back(0x00);
        }

        uint64_t bit_len = len * 8;
        for (int i = 7; i >= 0; --i) {
            padded_message.push_back((bit_len >> (i * 8)) & 0xff);
        }
        return padded_message;
    }
};

// 将哈希值向量转换为十六进制字符串
std::string to_hex_string(const std::vector<uint32_t>& hash_result) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (uint32_t val : hash_result) {
        oss << std::setw(8) << val;
    }
    return oss.str();
}

// 攻击者构造填充函数
std::vector<uint8_t> get_padding(size_t original_len) {
    std::vector<uint8_t> padding_bytes;
    size_t len_in_bits = original_len * 8;

    padding_bytes.push_back(0x80);

    while (((original_len + padding_bytes.size()) * 8) % 512 != 448) {
        padding_bytes.push_back(0x00);
    }

    uint64_t bit_len = len_in_bits;
    for (int i = 7; i >= 0; --i) {
        padding_bytes.push_back((bit_len >> (i * 8)) & 0xff);
    }
    return padding_bytes;
}

int main() {
    sm3 sm3;

    // ... 模拟场景 ...
    std::string secret = "i love SDU!";
    std::string data = "SDU love me!";
    std::string original_message = secret + data;

    // 1. 模拟服务器端计算哈希值
    std::vector<uint32_t> original_digest = sm3.hash(original_message);
    std::cout << "Original message: \"" << original_message << "\"" << std::endl;
    std::cout << "Original SM3 digest: " << to_hex_string(original_digest) << std::endl << std::endl;

    // --- 模拟攻击者 ---

    size_t original_len = original_message.length();
    std::string append_data = "i love Cyberspace Security!";

    // 攻击者构造的填充数据
    std::vector<uint8_t> padding_bytes = get_padding(original_len);

    // 攻击者真正要哈希的新消息是 `append_data`，但需要根据总长度进行填充
    size_t forged_message_len = original_len + padding_bytes.size() + append_data.length();
    std::vector<uint8_t> padded_append_data = get_padding(forged_message_len);

    // 将 append_data 和其填充数据合并
    std::vector<uint8_t> attack_block(append_data.begin(), append_data.end());
    attack_block.insert(attack_block.end(), padded_append_data.begin(), padded_append_data.end());

    // 攻击者使用原始哈希值作为新的初始哈希值
    std::vector<uint32_t> attack_iv = original_digest;

    // 循环处理 attack_block
    std::vector<uint32_t> forged_digest = attack_iv;
    for (size_t i = 0; i < attack_block.size(); i += 64) {
        std::vector<uint8_t> block(attack_block.begin() + i, attack_block.begin() + i + 64);
        forged_digest = sm3.cf(forged_digest, block);
    }

    // --- 验证结果 ---
    // ... 构造 forged_message 并重新计算 ...
    std::string forged_message = original_message;
    forged_message.insert(forged_message.end(), padding_bytes.begin(), padding_bytes.end());
    forged_message.append(append_data);

    std::cout << "Attacker's appended data: \"" << append_data << "\"" << std::endl;
    std::cout << "Attacker's forged message: \"" << original_message << "\" + PADDING + \"" << append_data << "\"" << std::endl;
    std::cout << "Attacker's forged digest:  " << to_hex_string(forged_digest) << std::endl;

    std::vector<uint32_t> real_digest = sm3.hash(forged_message);
    std::cout << "Real digest of forged msg: " << to_hex_string(real_digest) << std::endl << std::endl;

    if (to_hex_string(forged_digest) == to_hex_string(real_digest)) {
        std::cout << "Verification successful! The length extension attack on SM3 works." << std::endl;
    }
    else {
        std::cout << "Verification failed. The attack did not work." << std::endl;
    }

    return 0;
}