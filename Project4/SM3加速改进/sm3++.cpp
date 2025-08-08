#include <iostream>
#include <cstring>
#include <cstdint>
#include <iomanip>
#include <immintrin.h>
#include <vector>
#include <thread>
#include <algorithm>
#include <chrono>

namespace SM3_Utils {
    // Rotation and permutation functions
    inline uint32_t CircularShift(uint32_t value, int shift) {
        return (value << shift) | (value >> (32 - shift));
    }

    inline uint32_t Permute0(uint32_t x) {
        return x ^ CircularShift(x, 9) ^ CircularShift(x, 17);
    }

    inline uint32_t Permute1(uint32_t x) {
        return x ^ CircularShift(x, 15) ^ CircularShift(x, 23);
    }

    // Boolean functions
    inline uint32_t BoolFunc0(uint32_t x, uint32_t y, uint32_t z) {
        return x ^ y ^ z;
    }

    inline uint32_t BoolFunc1(uint32_t x, uint32_t y, uint32_t z) {
        return (x & y) | (x & z) | (y & z);
    }

    inline uint32_t BoolFunc2(uint32_t x, uint32_t y, uint32_t z) {
        return x ^ y ^ z;
    }

    inline uint32_t BoolFunc3(uint32_t x, uint32_t y, uint32_t z) {
        return (x & y) | ((~x) & z);
    }
}

// Constants for SM3 algorithm
namespace SM3_Constants {
    const uint32_t RoundConstants[64] = {
        0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519,
        0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519,
        0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
        0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
        0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
        0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
        0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
        0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A
    };

    const uint32_t InitialVector[8] = {
        0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
        0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
    };
}

// SIMD helper functions
namespace SIMD_Helpers {
    inline __m128i RotateLeft32(__m128i value, int shift) {
        return _mm_or_si128(_mm_slli_epi32(value, shift),
            _mm_srli_epi32(value, 32 - shift));
    }
}

class SM3_Hasher {
private:
    void ProcessBlock(uint32_t state[8], const uint8_t data_block[64]) {
        using namespace SM3_Utils;
        using namespace SM3_Constants;

        uint32_t message_schedule[68];

        // Load first 16 words
        for (int i = 0; i < 16; i++) {
            message_schedule[i] = (data_block[4 * i] << 24) |
                (data_block[4 * i + 1] << 16) |
                (data_block[4 * i + 2] << 8) |
                data_block[4 * i + 3];
        }

        // Expand message schedule
        for (int j = 16; j < 68; j++) {
            message_schedule[j] = Permute1(message_schedule[j - 16] ^
                message_schedule[j - 9] ^
                CircularShift(message_schedule[j - 3], 15)) ^
                CircularShift(message_schedule[j - 13], 7) ^
                message_schedule[j - 6];
        }

        // Compute W' array using SIMD
        uint32_t W_prime[64];
        for (int j = 0; j < 64; j += 4) {
            __m128i wj = _mm_loadu_si128((__m128i*)(message_schedule + j));
            __m128i wj4 = _mm_loadu_si128((__m128i*)(message_schedule + j + 4));
            __m128i w1 = _mm_xor_si128(wj, wj4);
            _mm_storeu_si128((__m128i*)(W_prime + j), w1);
        }

        uint32_t reg_A = state[0], reg_B = state[1], reg_C = state[2], reg_D = state[3];
        uint32_t reg_E = state[4], reg_F = state[5], reg_G = state[6], reg_H = state[7];

        // Main compression loop
        for (int round = 0; round < 64; round++) {
            __m128i const_vec = _mm_set1_epi32(RoundConstants[round]);
            __m128i w_vec = _mm_set1_epi32(message_schedule[round]);
            __m128i wp_vec = _mm_set1_epi32(W_prime[round]);

            uint32_t constant = _mm_extract_epi32(const_vec, 0);
            uint32_t w_val = _mm_extract_epi32(w_vec, 0);
            uint32_t wp_val = _mm_extract_epi32(wp_vec, 0);

            uint32_t SS1 = CircularShift((CircularShift(reg_A, 12) + reg_E +
                CircularShift(constant, round % 32)), 7);
            uint32_t SS2 = SS1 ^ CircularShift(reg_A, 12);

            uint32_t TT1, TT2;
            if (round < 16) {
                TT1 = BoolFunc0(reg_A, reg_B, reg_C) + reg_D + SS2 + wp_val;
                TT2 = BoolFunc2(reg_E, reg_F, reg_G) + reg_H + SS1 + w_val;
            }
            else {
                TT1 = BoolFunc1(reg_A, reg_B, reg_C) + reg_D + SS2 + wp_val;
                TT2 = BoolFunc3(reg_E, reg_F, reg_G) + reg_H + SS1 + w_val;
            }

            // Update registers
            reg_D = reg_C;
            reg_C = CircularShift(reg_B, 9);
            reg_B = reg_A;
            reg_A = TT1;
            reg_H = reg_G;
            reg_G = CircularShift(reg_F, 19);
            reg_F = reg_E;
            reg_E = Permute0(TT2);
        }

        // Update state
        state[0] ^= reg_A; state[1] ^= reg_B; state[2] ^= reg_C; state[3] ^= reg_D;
        state[4] ^= reg_E; state[5] ^= reg_F; state[6] ^= reg_G; state[7] ^= reg_H;
    }

    void ProcessMultipleBlocks(uint32_t* state, const uint8_t* data_blocks, size_t block_count) {
        for (size_t i = 0; i < block_count; i++) {
            ProcessBlock(state, data_blocks + i * 64);
        }
    }

public:
    void ComputeHash(const uint8_t* message, size_t length, uint8_t digest[32]) {
        using namespace SM3_Constants;

        const uint64_t bit_length = static_cast<uint64_t>(length) * 8;
        const size_t padded_length = ((length + 1 + 8 + 63) / 64) * 64;
        uint8_t* padded_message = new uint8_t[padded_length]();

        std::memcpy(padded_message, message, length);
        padded_message[length] = 0x80;

        for (int i = 0; i < 8; ++i) {
            padded_message[padded_length - 8 + i] = (bit_length >> ((7 - i) * 8)) & 0xFF;
        }

        uint32_t hash_state[8];
        std::memcpy(hash_state, InitialVector, sizeof(InitialVector));

        const size_t total_blocks = padded_length / 64;
        const size_t thread_count = std::min<size_t>(std::thread::hardware_concurrency(), total_blocks);

        if (total_blocks < 128 || thread_count <= 1) {
            ProcessMultipleBlocks(hash_state, padded_message, total_blocks);
        }
        else {
            std::vector<std::vector<uint32_t>> thread_states(thread_count,
                std::vector<uint32_t>(8));

            for (size_t i = 0; i < thread_count; i++) {
                std::memcpy(thread_states[i].data(), InitialVector, sizeof(InitialVector));
            }

            const size_t base_blocks_per_thread = total_blocks / thread_count;
            const size_t extra_blocks = total_blocks % thread_count;

            std::vector<std::thread> workers;
            size_t block_offset = 0;

            for (size_t i = 0; i < thread_count; i++) {
                size_t blocks_to_process = base_blocks_per_thread + (i < extra_blocks ? 1 : 0);
                if (blocks_to_process == 0) continue;

                workers.emplace_back([&, i, block_offset, blocks_to_process]() {
                    ProcessMultipleBlocks(thread_states[i].data(),
                        padded_message + block_offset * 64,
                        blocks_to_process);
                    });

                block_offset += blocks_to_process;
            }

            for (auto& worker : workers) {
                worker.join();
            }

            std::memcpy(hash_state, InitialVector, sizeof(InitialVector));
            for (size_t i = 0; i < thread_count; i++) {
                uint8_t state_block[64];
                for (int j = 0; j < 8; j++) {
                    state_block[4 * j] = (thread_states[i][j] >> 24) & 0xFF;
                    state_block[4 * j + 1] = (thread_states[i][j] >> 16) & 0xFF;
                    state_block[4 * j + 2] = (thread_states[i][j] >> 8) & 0xFF;
                    state_block[4 * j + 3] = thread_states[i][j] & 0xFF;
                }
                ProcessBlock(hash_state, state_block);
            }
        }

        delete[] padded_message;

        // Convert state to byte array
        for (int i = 0; i < 8; ++i) {
            digest[4 * i] = (hash_state[i] >> 24) & 0xFF;
            digest[4 * i + 1] = (hash_state[i] >> 16) & 0xFF;
            digest[4 * i + 2] = (hash_state[i] >> 8) & 0xFF;
            digest[4 * i + 3] = hash_state[i] & 0xFF;
        }
    }

    static void DisplayDigest(const uint8_t digest[32]) {
        for (int i = 0; i < 32; ++i) {
            std::cout << std::hex << std::setw(2) << std::setfill('0')
                << static_cast<int>(digest[i]);
        }
        std::cout << std::endl;
    }
};

int main() {
    const char* test_message = "abc";
    uint8_t result[32];

    auto timer_start = std::chrono::high_resolution_clock::now();

    SM3_Hasher hasher;
    hasher.ComputeHash(reinterpret_cast<const uint8_t*>(test_message),
        std::strlen(test_message), result);

    auto timer_end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::milli> duration = timer_end - timer_start;

    std::cout << "Input message: " << test_message << std::endl;
    std::cout << "SM3 hash result: ";
    SM3_Hasher::DisplayDigest(result);

    std::cout << "Computation time: " << duration.count() << " ms" << std::endl;

    return 0;
}