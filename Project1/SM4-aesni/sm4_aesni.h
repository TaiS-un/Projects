#ifndef SM4_AESNI_COMBINED_H
#define SM4_AESNI_COMBINED_H

#include <stdint.h>

/**
 * @brief SM4 ��Կ
 */
typedef struct _SM4_Key {
    uint32_t rk[32]; // 32����Կ
} SM4_Key;

/**
 * @brief ��ʼ�� SM4 ����Կ
 * @param key 128bit������Կ
 * @param sm4_key SM4 ��Կ
 */
void SM4_KeyInit(uint8_t* key, SM4_Key* sm4_key);

void SM4_AESNI_Encrypt_x4(uint8_t* plaintext, uint8_t* ciphertext, SM4_Key* sm4_key);

void SM4_AESNI_Decrypt_x4(uint8_t* ciphertext, uint8_t* plaintext, SM4_Key* sm4_key);

#endif // !SM4_AESNI_COMBINED_H