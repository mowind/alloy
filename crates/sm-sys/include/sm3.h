
#ifndef HEADER_SM3_H
#define HEADER_SM3_H

#define SM3_SSE3

#define SM3_DIGEST_LENGTH	32
#define SM3_BLOCK_SIZE		64

#include <stdint.h>
#include <string.h>

typedef struct {
    uint32_t digest[8];
    int nblocks;
    unsigned char block[64];
    int num;
} sm3_ctx_t;

#define u8_to_u32(x) ((uint32_t)((x)[0]))<<24 |  ((uint32_t)((x)[1]))<<16 |((uint32_t)((x)[2]))<<8 |((uint32_t)((x)[3]))
#define u32_to_u8(y, x) {\
    (y)[0] = (uint8_t)(((x)>>24)&0xff);\
    (y)[1] = (uint8_t)(((x)>>16)&0xff);\
    (y)[2] = (uint8_t)(((x)>>8)&0xff);\
    (y)[3] = (uint8_t)((x)&0xff);\
}
#define ROL32(a,n)  ({ register unsigned int ret;                     \
                                asm (                                 \
                                "roll %1,%0"                          \
                                : "=r"(ret)                           \
                                : "I"(n), "0"((unsigned int)(a))      \
                                : "cc");                              \
                           ret;                                       \
                        })

#ifdef __cplusplus
extern "C" {
#endif

void sm3_init(sm3_ctx_t *ctx);
void sm3_update(sm3_ctx_t *ctx, const unsigned char* data, size_t data_len);
void sm3_final(sm3_ctx_t *ctx, unsigned char digest[SM3_DIGEST_LENGTH]);
void sm3_compress(uint32_t digest[8], const unsigned char block[SM3_BLOCK_SIZE]);
void sm3(const unsigned char *data, size_t datalen,
         unsigned char digest[SM3_DIGEST_LENGTH]);

#ifdef __cplusplus
}
#endif

#endif