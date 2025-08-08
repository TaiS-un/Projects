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

	std::vector<uint32_t> hash(const std::string& message) {

		std::vector<uint8_t> padded_message = padding(message);



		std::vector<uint32_t> h = initial_h;

		for (size_t i = 0; i < padded_message.size(); i += 64) {

			std::vector<uint8_t> block(padded_message.begin() + i, padded_message.begin() + i + 64);

			h = cf(h, block);

		}

		return h;

	}



private:

	const std::vector<uint32_t> initial_h = {

		0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,

		0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e

	};



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

};



std::string to_hex_string(const std::vector<uint32_t>& hash_result) {

	std::ostringstream oss;

	oss << std::hex << std::setfill('0');

	for (uint32_t val : hash_result) {

		oss << std::setw(8) << val;

	}

	return oss.str();

}



int main() {

	sm3 sm3;

	std::string message = "abc";



	auto start = std::chrono::high_resolution_clock::now();

	std::vector<uint32_t> digest = sm3.hash(message);

	auto end = std::chrono::high_resolution_clock::now();

	std::chrono::duration<double> duration = end - start;



	std::cout << "消息: " << message << std::endl;

	std::cout << "sm3 哈希值: " << to_hex_string(digest) << std::endl;

	std::cout << "计算时间: " << duration.count() * 1000 << " 毫秒" << std::endl;



	return 0;

}