/*
 * GenMatrix.c
 * 零依赖版：内建了 memcpy/memset，无需 string.h
 */

#include <stdint.h>
#include <stdbool.h>

// 1. 手动实现标准库函数 (Zero Dependency)
// 使用编译器内置类型定义 size_t，兼容 32/64 位
typedef __SIZE_TYPE__ size_t;

// 手写 memcpy，避免依赖 string.h
void *memcpy(void *dst, const void *src, size_t n) {
    uint8_t *d = (uint8_t *)dst;
    const uint8_t *s = (const uint8_t *)src;
    while (n--) {
        *d++ = *s++;
    }
    return dst;
}

// 手写 memset，避免依赖 string.h
void *memset(void *dst, int c, size_t n) {
    uint8_t *d = (uint8_t *)dst;
    while (n--) {
        *d++ = (uint8_t)c;
    }
    return dst;
}
// 2. 常量与宏定义

#define MLKEM_N 256
#define MLKEM_Q 3329
#define MLKEM_K_MAX 4       
#define MLKEM_SEED_LEN 32   
#define MLKEM_XOF_OUTPUT_LENGTH 1000 

#define CRYPT_SUCCESS 0
#define CRYPT_MLKEM_KEYLEN_ERROR (-1)

#define RETURN_RET_IF(condition, retval) if (condition) return retval;
#define BSL_ERR_PUSH_ERROR(code) 

// 映射 memcpy_s 到我们手写的 memcpy
#define memcpy_s(dest, destsz, src, count) memcpy(dest, src, count)

// 3. 结构体定义

typedef struct {
    uint8_t k; 
} CRYPT_MLKEM_Info;

typedef struct {
    const CRYPT_MLKEM_Info *info;
    void *libCtx; 
} CRYPT_MLKEM_Ctx;

// 4. Mock 函数

/**
 * [MOCK] HashFuncXOF
 * SAW 验证时会被 Override 替换，这里的实现仅为编译通过。
 */
int32_t HashFuncXOF(void *libCtx, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t outLen)
{
    if (out != (void*)0) {
        memset(out, 0, outLen);
    }
    return CRYPT_SUCCESS;
}

/**
 * Parse
 */
int32_t Parse(uint16_t *polyNtt, uint8_t *arrayB, uint32_t arrayLen, uint32_t n)
{
    uint32_t i = 0;
    uint32_t j = 0;
    while (j < n) {
        if (i + 3 > arrayLen) {
            BSL_ERR_PUSH_ERROR(CRYPT_MLKEM_KEYLEN_ERROR);
            return CRYPT_MLKEM_KEYLEN_ERROR;
        }
        uint16_t d1 = ((uint16_t)arrayB[i]) + (((uint16_t)arrayB[i + 1] & 0x0f) << 8);
        uint16_t d2 = (((uint16_t)arrayB[i + 1]) >> 4) + (((uint16_t)arrayB[i + 2]) << 4);
        if (d1 < MLKEM_Q) {
            polyNtt[j] = d1;
            j++;
        }
        if (d2 < MLKEM_Q && j < n) {
            polyNtt[j] = d2;
            j++;
        }
        i += 3;
    }
    return CRYPT_SUCCESS;
}

// 5. 目标函数 GenMatrix

int32_t GenMatrix(const CRYPT_MLKEM_Ctx *ctx, const uint8_t *digest,
                  int16_t *polyMatrix[MLKEM_K_MAX][MLKEM_K_MAX], bool isEnc)
{
    uint8_t k = ctx->info->k;
    
    uint8_t p[MLKEM_SEED_LEN + 2];
    uint8_t xofOut[MLKEM_XOF_OUTPUT_LENGTH];

    (void)memcpy_s(p, MLKEM_SEED_LEN, digest, MLKEM_SEED_LEN);
    
    for (uint8_t i = 0; i < k; i++) {
        for (uint8_t j = 0; j < k; j++) {
            if (isEnc) {
                // Encrypt: i, j
                p[MLKEM_SEED_LEN] = i;
                p[MLKEM_SEED_LEN + 1] = j;
            } else {
                // KeyGen: j, i
                p[MLKEM_SEED_LEN] = j;
                p[MLKEM_SEED_LEN + 1] = i;
            }
            
            int32_t ret = HashFuncXOF(ctx->libCtx, p, MLKEM_SEED_LEN + 2, xofOut, MLKEM_XOF_OUTPUT_LENGTH);
            RETURN_RET_IF(ret != CRYPT_SUCCESS, ret);
            
            ret = Parse((uint16_t *)polyMatrix[i][j], xofOut, MLKEM_XOF_OUTPUT_LENGTH, MLKEM_N);
            RETURN_RET_IF(ret != CRYPT_SUCCESS, ret);
        }
    }
    return CRYPT_SUCCESS;
}