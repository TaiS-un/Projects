#include "sm4_gcm.h"
#include <stdio.h>
#include <string.h>
#include<time.h>

void print_hex(const char* label, const uint8_t* data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int main() {
    // 测试数据
    uint8_t key[SM4_KEY_SIZE] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    uint8_t iv[SM4_GCM_IV_SIZE] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b
    };

    uint8_t aad[] = { 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef };
    uint8_t plaintext[] = "Hello, SM4-GCM! This is a test message.";
    size_t plaintext_len = strlen((char*)plaintext);

    uint8_t ciphertext[128] = { 0 };
    uint8_t decrypted[128] = { 0 };
    uint8_t tag[SM4_GCM_TAG_SIZE] = { 0 };

    clock_t start, end;
    double cpu_time_used;
    const int iterations = 10000; // 循环次数

    // 1. 测量初始化时间
    start = clock();
    for (int i = 0; i < iterations; i++) {
        sm4_gcm_ctx ctx;
        sm4_gcm_init(&ctx, key, iv, sizeof(iv));
    }
    end = clock();
    cpu_time_used = ((double)(end - start)) / CLOCKS_PER_SEC;
    printf("初始化平均时间: %.8f 秒\n", cpu_time_used / iterations);

    // 初始化上下文
    sm4_gcm_ctx ctx;
    sm4_gcm_init(&ctx, key, iv, sizeof(iv));

    // 2. 测量加密时间
    start = clock();
    for (int i = 0; i < iterations; i++) {
        sm4_gcm_encrypt(&ctx, ciphertext, plaintext, plaintext_len, aad, sizeof(aad), tag);
    }
    end = clock();
    cpu_time_used = ((double)(end - start)) / CLOCKS_PER_SEC;
    printf("加密平均时间: %.8f 秒\n", cpu_time_used / iterations);

    print_hex("Plaintext", plaintext, plaintext_len);
    print_hex("Ciphertext", ciphertext, plaintext_len);
    print_hex("Tag", tag, sizeof(tag));

    // 3. 测量解密时间
    start = clock();
    int ret = 0;
    for (int i = 0; i < iterations; i++) {
        ret = sm4_gcm_decrypt(&ctx, decrypted, ciphertext, plaintext_len, aad, sizeof(aad), tag);
    }
    end = clock();
    cpu_time_used = ((double)(end - start)) / CLOCKS_PER_SEC;
    printf("解密平均时间: %.8f 秒\n", cpu_time_used / iterations);

    if (ret == 0) {
        printf("Decryption successful!\n");
        print_hex("Decrypted", decrypted, plaintext_len);
        printf("Decrypted text: %s\n", decrypted);
    }
    else {
        printf("Authentication failed!\n");
    }

    return 0;
}