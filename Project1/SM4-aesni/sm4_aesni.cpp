#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <immintrin.h>
#include <time.h> 
#include "sm4_aesni.h"
#include <string.h>
// sm4.c 的内容
static uint32_t FK[4] = { 0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc };
static uint32_t CK[32] = {
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269, 0x70777e85, 0x8c939aa1,
    0xa8afb6bd, 0xc4cbd2d9, 0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
    0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9, 0xc0c7ced5, 0xdce3eaf1,
    0xf8ff060d, 0x141b2229, 0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209, 0x10171e25, 0x2c333a41,
    0x484f565d, 0x646b7279 };
static uint8_t SBox[256] = {
    0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7, 0x16, 0xB6, 0x14, 0xC2,
    0x28, 0xFB, 0x2C, 0x05, 0x2B, 0x67, 0x9A, 0x76, 0x2A, 0xBE, 0x04, 0xC3,
    0xAA, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99, 0x9C, 0x42, 0x50, 0xF4,
    0x91, 0xEF, 0x98, 0x7A, 0x33, 0x54, 0x0B, 0x43, 0xED, 0xCF, 0xAC, 0x62,
    0xE4, 0xB3, 0x1C, 0xA9, 0xC9, 0x08, 0xE8, 0x95, 0x80, 0xDF, 0x94, 0xFA,
    0x75, 0x8F, 0x3F, 0xA6, 0x47, 0x07, 0xA7, 0xFC, 0xF3, 0x73, 0x17, 0xBA,
    0x83, 0x59, 0x3C, 0x19, 0xE6, 0x85, 0x4F, 0xA8, 0x68, 0x6B, 0x81, 0xB2,
    0x71, 0x64, 0xDA, 0x8B, 0xF8, 0xEB, 0x0F, 0x4B, 0x70, 0x56, 0x9D, 0x35,
    0x1E, 0x24, 0x0E, 0x5E, 0x63, 0x58, 0xD1, 0xA2, 0x25, 0x22, 0x7C, 0x3B,
    0x01, 0x21, 0x78, 0x87, 0xD4, 0x00, 0x46, 0x57, 0x9F, 0xD3, 0x27, 0x52,
    0x4C, 0x36, 0x02, 0xE7, 0xA0, 0xC4, 0xC8, 0x9E, 0xEA, 0xBF, 0x8A, 0xD2,
    0x40, 0xC7, 0x38, 0xB5, 0xA3, 0xF7, 0xF2, 0xCE, 0xF9, 0x61, 0x15, 0xA1,
    0xE0, 0xAE, 0x5D, 0xA4, 0x9B, 0x34, 0x1A, 0x55, 0xAD, 0x93, 0x32, 0x30,
    0xF5, 0x8C, 0xB1, 0xE3, 0x1D, 0xF6, 0xE2, 0x2E, 0x82, 0x66, 0xCA, 0x60,
    0xC0, 0x29, 0x23, 0xAB, 0x0D, 0x53, 0x4E, 0x6F, 0xD5, 0xDB, 0x37, 0x45,
    0xDE, 0xFD, 0x8E, 0x2F, 0x03, 0xFF, 0x6A, 0x72, 0x6D, 0x6C, 0x5B, 0x51,
    0x8D, 0x1B, 0xAF, 0x92, 0xBB, 0xDD, 0xBC, 0x7F, 0x11, 0xD9, 0x5C, 0x41,
    0x1F, 0x10, 0x5A, 0xD8, 0x0A, 0xC1, 0x31, 0x88, 0xA5, 0xCD, 0x7B, 0xBD,
    0x2D, 0x74, 0xD0, 0x12, 0xB8, 0xE5, 0xB4, 0xB0, 0x89, 0x69, 0x97, 0x4A,
    0x0C, 0x96, 0x77, 0x7E, 0x65, 0xB9, 0xF1, 0x09, 0xC5, 0x6E, 0xC6, 0x84,
    0x18, 0xF0, 0x7D, 0xEC, 0x3A, 0xDC, 0x4D, 0x20, 0x79, 0xEE, 0x5F, 0x3E,
    0xD7, 0xCB, 0x39, 0x48 };

#define rotl32(value, shift) ((value << shift) | value >> (32 - shift))

void SM4_KeyInit(uint8_t* key, SM4_Key* sm4_key) {
    uint32_t k[4];
    uint32_t tmp;
    uint8_t* tmp_ptr8 = (uint8_t*)&tmp;
    // 初始化密钥
    for (int i = 0; i < 4; i++) {
        int j = 4 * i;
        k[i] = (key[j + 0] << 24) | (key[j + 1] << 16) | (key[j + 2] << 8) |
            (key[j + 3]);
        k[i] = k[i] ^ FK[i];
    }
    // 32轮变换
    for (int i = 0; i < 32; i++) {
        tmp = k[1] ^ k[2] ^ k[3] ^ CK[i];
        // SBox 盒变换
        for (int j = 0; j < 4; j++) {
            tmp_ptr8[j] = SBox[tmp_ptr8[j]];
        }
        // 线性变换
        sm4_key->rk[i] = k[0] ^ tmp ^ rotl32(tmp, 13) ^ rotl32(tmp, 23);
        // 移位
        k[0] = k[1];
        k[1] = k[2];
        k[2] = k[3];
        k[3] = sm4_key->rk[i];
    }
}

// sm4_aesni_x4.c 的内容
static void SM4_AESNI_do(uint8_t* in, uint8_t* out, SM4_Key* sm4_key, int enc);

void SM4_AESNI_Encrypt_x4(uint8_t* plaintext, uint8_t* ciphertext,
    SM4_Key* sm4_key) {
    SM4_AESNI_do(plaintext, ciphertext, sm4_key, 0);
}

void SM4_AESNI_Decrypt_x4(uint8_t* ciphertext, uint8_t* plaintext,
    SM4_Key* sm4_key) {
    SM4_AESNI_do(ciphertext, plaintext, sm4_key, 1);
}

#define MM_PACK0_EPI32(a, b, c, d) \
    _mm_unpacklo_epi64(_mm_unpacklo_epi32(a, b), _mm_unpacklo_epi32(c, d))
#define MM_PACK1_EPI32(a, b, c, d) \
    _mm_unpackhi_epi64(_mm_unpacklo_epi32(a, b), _mm_unpacklo_epi32(c, d))
#define MM_PACK2_EPI32(a, b, c, d) \
    _mm_unpacklo_epi64(_mm_unpackhi_epi32(a, b), _mm_unpackhi_epi32(c, d))
#define MM_PACK3_EPI32(a, b, c, d) \
    _mm_unpackhi_epi64(_mm_unpackhi_epi32(a, b), _mm_unpackhi_epi32(c, d))

#define MM_XOR2(a, b) _mm_xor_si128(a, b)
#define MM_XOR3(a, b, c) MM_XOR2(a, MM_XOR2(b, c))
#define MM_XOR4(a, b, c, d) MM_XOR2(a, MM_XOR3(b, c, d))
#define MM_XOR5(a, b, c, d, e) MM_XOR2(a, MM_XOR4(b, c, d, e))
#define MM_XOR6(a, b, c, d, e, f) MM_XOR2(a, MM_XOR5(b, c, d, e, f))
#define MM_ROTL_EPI32(a, n) \
    MM_XOR2(_mm_slli_epi32(a, n), _mm_srli_epi32(a, 32 - n))

static __m128i SM4_SBox(__m128i x);

static __m128i MulMatrix(__m128i x, __m128i higherMask, __m128i lowerMask) {
    __m128i tmp1, tmp2;
    __m128i andMask = _mm_set1_epi32(0x0f0f0f0f);
    tmp2 = _mm_srli_epi16(x, 4);
    tmp1 = _mm_and_si128(x, andMask);
    tmp2 = _mm_and_si128(tmp2, andMask);
    tmp1 = _mm_shuffle_epi8(lowerMask, tmp1);
    tmp2 = _mm_shuffle_epi8(higherMask, tmp2);
    tmp1 = _mm_xor_si128(tmp1, tmp2);
    return tmp1;
}

static __m128i MulMatrixATA(__m128i x) {
    __m128i higherMask =
        _mm_set_epi8(0x14, 0x07, 0xc6, 0xd5, 0x6c, 0x7f, 0xbe, 0xad, 0xb9, 0xaa,
            0x6b, 0x78, 0xc1, 0xd2, 0x13, 0x00);
    __m128i lowerMask =
        _mm_set_epi8(0xd8, 0xb8, 0xfa, 0x9a, 0xc5, 0xa5, 0xe7, 0x87, 0x5f, 0x3f,
            0x7d, 0x1d, 0x42, 0x22, 0x60, 0x00);
    return MulMatrix(x, higherMask, lowerMask);
}

static __m128i MulMatrixTA(__m128i x) {
    __m128i higherMask =
        _mm_set_epi8(0x22, 0x58, 0x1a, 0x60, 0x02, 0x78, 0x3a, 0x40, 0x62, 0x18,
            0x5a, 0x20, 0x42, 0x38, 0x7a, 0x00);
    __m128i lowerMask =
        _mm_set_epi8(0xe2, 0x28, 0x95, 0x5f, 0x69, 0xa3, 0x1e, 0xd4, 0x36, 0xfc,
            0x41, 0x8b, 0xbd, 0x77, 0xca, 0x00);
    return MulMatrix(x, higherMask, lowerMask);
}

static __m128i AddTC(__m128i x) {
    __m128i TC = _mm_set1_epi8(0b00100011);
    return _mm_xor_si128(x, TC);
}

static __m128i AddATAC(__m128i x) {
    __m128i ATAC = _mm_set1_epi8(0b00111011);
    return _mm_xor_si128(x, ATAC);
}

static __m128i SM4_SBox(__m128i x) {
    __m128i MASK = _mm_set_epi8(0x03, 0x06, 0x09, 0x0c, 0x0f, 0x02, 0x05, 0x08,
        0x0b, 0x0e, 0x01, 0x04, 0x07, 0x0a, 0x0d, 0x00);
    x = _mm_shuffle_epi8(x, MASK);  // 逆行移位
    x = AddTC(MulMatrixTA(x));
    x = _mm_aesenclast_si128(x, _mm_setzero_si128());
    return AddATAC(MulMatrixATA(x));
}

static void SM4_AESNI_do(uint8_t* in, uint8_t* out, SM4_Key* sm4_key, int enc) {
    __m128i X[4], Tmp[4];
    __m128i vindex;
    // Load Data
    Tmp[0] = _mm_loadu_si128((const __m128i*)in + 0);
    Tmp[1] = _mm_loadu_si128((const __m128i*)in + 1);
    Tmp[2] = _mm_loadu_si128((const __m128i*)in + 2);
    Tmp[3] = _mm_loadu_si128((const __m128i*)in + 3);
    vindex =
        _mm_setr_epi8(3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12);
    // Pack Data
    X[0] = MM_PACK0_EPI32(Tmp[0], Tmp[1], Tmp[2], Tmp[3]);
    X[1] = MM_PACK1_EPI32(Tmp[0], Tmp[1], Tmp[2], Tmp[3]);
    X[2] = MM_PACK2_EPI32(Tmp[0], Tmp[1], Tmp[2], Tmp[3]);
    X[3] = MM_PACK3_EPI32(Tmp[0], Tmp[1], Tmp[2], Tmp[3]);
    // Shuffle Endian
    X[0] = _mm_shuffle_epi8(X[0], vindex);
    X[1] = _mm_shuffle_epi8(X[1], vindex);
    X[2] = _mm_shuffle_epi8(X[2], vindex);
    X[3] = _mm_shuffle_epi8(X[3], vindex);
    // Loop
    for (int i = 0; i < 32; i++) {
        __m128i k =
            _mm_set1_epi32((enc == 0) ? sm4_key->rk[i] : sm4_key->rk[31 - i]);
        Tmp[0] = MM_XOR4(X[1], X[2], X[3], k);
        // SBox
        Tmp[0] = SM4_SBox(Tmp[0]);
        // L
        Tmp[0] = MM_XOR6(X[0], Tmp[0], MM_ROTL_EPI32(Tmp[0], 2),
            MM_ROTL_EPI32(Tmp[0], 10), MM_ROTL_EPI32(Tmp[0], 18),
            MM_ROTL_EPI32(Tmp[0], 24));
        //
        X[0] = X[1];
        X[1] = X[2];
        X[2] = X[3];
        X[3] = Tmp[0];
    }
    // Shuffle Endian
    X[0] = _mm_shuffle_epi8(X[0], vindex);
    X[1] = _mm_shuffle_epi8(X[1], vindex);
    X[2] = _mm_shuffle_epi8(X[2], vindex);
    X[3] = _mm_shuffle_epi8(X[3], vindex);
    // Pack and Store
    _mm_storeu_si128((__m128i*)out + 0, MM_PACK0_EPI32(X[3], X[2], X[1], X[0]));
    _mm_storeu_si128((__m128i*)out + 1, MM_PACK1_EPI32(X[3], X[2], X[1], X[0]));
    _mm_storeu_si128((__m128i*)out + 2, MM_PACK2_EPI32(X[3], X[2], X[1], X[0]));
    _mm_storeu_si128((__m128i*)out + 3, MM_PACK3_EPI32(X[3], X[2], X[1], X[0]));
}



int main() {
    SM4_Key sm4_key;
    unsigned char key[16] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
                             0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 };
    unsigned char plaintext[16 * 4] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 };
    unsigned char ciphertext[16 * 4];
    unsigned char decrypted_text[16 * 4];
    int i;

    clock_t start, end;
    double cpu_time_used;
    const int iterations = 100000; // 循环次数

    // 1. 测量密钥扩展时间
    start = clock();
    for (i = 0; i < iterations; ++i) {
        SM4_KeyInit(key, &sm4_key);
    }
    end = clock();
    cpu_time_used = ((double)(end - start)) / CLOCKS_PER_SEC;
    printf("密钥扩展平均时间: %.8f 秒\n", cpu_time_used / iterations);

    // 2. 加密过程
    start = clock();
    for (i = 0; i < iterations; ++i) {
        SM4_AESNI_Encrypt_x4(plaintext, ciphertext, &sm4_key);
    }
    end = clock();
    cpu_time_used = ((double)(end - start)) / CLOCKS_PER_SEC;
    printf("加密平均时间: %.8f 秒\n", cpu_time_used / iterations);

    printf("原始明文 (Plaintext): \n");
    for (i = 0; i < 16; i++) {
        printf("%02x ", plaintext[i]);
    }
    printf("\n\n");

    printf("加密结果 (Ciphertext): \n");
    for (i = 0; i < 16; i++) {
        printf("%02x ", ciphertext[i]);
    }
    printf("\n\n");

    // 3. 解密过程
    start = clock();
    for (i = 0; i < iterations; ++i) {
        SM4_AESNI_Decrypt_x4(ciphertext, decrypted_text, &sm4_key);
    }
    end = clock();
    cpu_time_used = ((double)(end - start)) / CLOCKS_PER_SEC;
    printf("解密平均时间: %.8f 秒\n", cpu_time_used / iterations);

    // 4. 输出解密结果
    printf("解密结果 (Decrypted Text): \n");
    for (i = 0; i < 16; i++) {
        printf("%02x ", decrypted_text[i]);
    }
    printf("\n\n");

    // 5. 验证解密结果
    if (memcmp(plaintext, decrypted_text, 16) == 0) {
        printf("验证成功：解密结果与原始明文一致。\n");
    }
    else {
        printf("验证失败：解密结果与原始明文不一致！\n");
    }

    return 0;
}