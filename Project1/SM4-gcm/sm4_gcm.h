#ifndef SM4_GCM_H
#define SM4_GCM_H

#include <stdint.h>
#include <stdlib.h>

#define SM4_BLOCK_SIZE 16
#define SM4_KEY_SIZE 16
#define SM4_GCM_IV_SIZE 12
#define SM4_GCM_TAG_SIZE 16

// ѭ�����ƺ�
#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

typedef struct {
    uint32_t rk[32];        // SM4����Կ
    uint8_t H[16];          // GHASHʹ�õ�Hֵ
    uint8_t J0[16];         // ��ʼ������ֵ
    uint64_t aad_len;       // AAD����(�ֽ�)
    uint64_t cipher_len;    // ���ĳ���(�ֽ�)
} sm4_gcm_ctx;

void sm4_gcm_init(sm4_gcm_ctx* ctx, const uint8_t* key, const uint8_t* iv, size_t iv_len);
int sm4_gcm_encrypt(sm4_gcm_ctx* ctx, uint8_t* out, const uint8_t* in, size_t len,
    const uint8_t* aad, size_t aad_len, uint8_t* tag);
int sm4_gcm_decrypt(sm4_gcm_ctx* ctx, uint8_t* out, const uint8_t* in, size_t len,
    const uint8_t* aad, size_t aad_len, const uint8_t* tag);

#endif // SM4_GCM_H