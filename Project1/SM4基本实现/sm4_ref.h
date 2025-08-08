#ifndef SM4_REF_H
#define SM4_REF_H

#include <stdint.h>

#define SM4_KEY_LEN      16   /* 128 bit */
#define SM4_BLOCK_LEN    16   /* 128 bit */
#define SM4_ROUNDS       32   /* 固定 32 轮 */

/* 设置 128 bit 用户密钥，生成 32 轮扩展密钥 rk[32] */
void sm4_setkey_enc(uint32_t rk[SM4_ROUNDS], const uint8_t key[SM4_KEY_LEN]);

/* 解密时只需把 rk 逆序即可 */
static inline void sm4_setkey_dec(uint32_t rk[SM4_ROUNDS], const uint32_t enc_rk[SM4_ROUNDS])
{
    for (int i = 0; i < SM4_ROUNDS; ++i)
        rk[i] = enc_rk[SM4_ROUNDS - 1 - i];
}

/* ECB 单块加密：in/out 指向 16 byte */
void sm4_crypt_ecb(const uint32_t rk[SM4_ROUNDS],
    const uint8_t in[SM4_BLOCK_LEN],
    uint8_t out[SM4_BLOCK_LEN]);

#endif /* SM4_REF_H */