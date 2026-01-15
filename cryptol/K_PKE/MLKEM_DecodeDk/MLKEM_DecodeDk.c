#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
// #include <stdlib.h>
// #include <string.h>

// ==========================================
// 1. 宏定义
// ==========================================
#define MLKEM_N           256
#define MLKEM_K_MAX       4
#define MLKEM_Q           3329

// 常量定义，确保偏移量计算正确
// OFFSET = 32 * 12 = 384
#define MLKEM_SEED_LEN    32
#define MLKEM_BITS_OF_Q   12
#define MLKEM_CIPHER_LEN  384 

#define CRYPT_SUCCESS     0
#define CRYPT_ERROR       -1

// 错误码
#define CRYPT_NULL_INPUT                -1001
#define CRYPT_MLKEM_KEYINFO_NOT_SET     -1002
#define CRYPT_MLKEM_KEYLEN_ERROR        -1003
#define BSL_MALLOC_FAIL                 -1004
#define CRYPT_MLKEM_DECODE_KEY_OVERFLOW -1005

// Mock Macros
#define BSL_SAL_Calloc(num, size) calloc(num, size)
#define BSL_ERR_PUSH_ERROR(code) 

// ==========================================
// 2. 数据结构
// ==========================================
typedef struct {
    int16_t *bufAddr; 
    int16_t *matrix[MLKEM_K_MAX][MLKEM_K_MAX];
    int16_t *vectorS[MLKEM_K_MAX];
    int16_t *vectorE[MLKEM_K_MAX];
    int16_t *vectorT[MLKEM_K_MAX];
} MLKEM_MatrixSt;

typedef struct {
    uint8_t k;
    uint8_t eta1;
    uint8_t eta2;
    uint8_t du;
    uint8_t dv;
    uint32_t secBits;
    uint32_t encapsKeyLen;
    uint32_t decapsKeyLen;
    uint32_t cipherLen;
    uint32_t sharedLen;
    uint32_t bits;
} CRYPT_MlKemInfo;

typedef struct CryptMlKemCtx {
    int32_t algId;
    const CRYPT_MlKemInfo *info;
    uint8_t *ek;
    uint32_t ekLen;
    uint8_t *dk;
    uint32_t dkLen;
    void *libCtx;
    MLKEM_MatrixSt keyData;
} CRYPT_ML_KEM_Ctx;

// ==========================================
// 3. 依赖函数声明
// ==========================================
int32_t GenMatrix(const CRYPT_ML_KEM_Ctx *ctx, const uint8_t *digest,
    int16_t *polyMatrix[MLKEM_K_MAX][MLKEM_K_MAX], bool isEnc);

// ==========================================
// 4. 辅助函数实现
// ==========================================

int32_t MLKEM_CreateMatrixBuf(uint8_t k, MLKEM_MatrixSt *st)
{
    if (st->bufAddr != NULL) return CRYPT_SUCCESS;
    size_t total_polys = (size_t)(k * k + 3 * k);
    int16_t *buf = (int16_t *)BSL_SAL_Calloc(total_polys * MLKEM_N, sizeof(int16_t));
    if (buf == NULL) return BSL_MALLOC_FAIL;
    st->bufAddr = buf;
    
    for (uint8_t i = 0; i < k; i++) {
        for (uint8_t j = 0; j < k; j++) {
            st->matrix[i][j] = buf + (i * k + j) * MLKEM_N;
        }
        st->vectorS[i] = buf + (k * k + i * 3) * MLKEM_N;
        st->vectorE[i] = buf + (k * k + i * 3 + 1) * MLKEM_N;
        st->vectorT[i] = buf + (k * k + i * 3 + 2) * MLKEM_N;
    }
    return CRYPT_SUCCESS;
}

static int32_t DecodeBits12(int16_t *polyF, const uint8_t *a)
{
    uint32_t i;
    for (i = 0; i < MLKEM_N / 2; i++) {
        polyF[2 * i] = ((a[3 * i + 0] >> 0) | ((uint16_t)a[3 * i + 1] << 8)) & 0xFFF;
        polyF[2 * i + 1] = ((a[3 * i + 1] >> 4) | ((uint16_t)a[3 * i + 2] << 4)) & 0xFFF;
        if (polyF[2 * i] >= MLKEM_Q || polyF[2 * i + 1] >= MLKEM_Q) {
            return CRYPT_MLKEM_DECODE_KEY_OVERFLOW;
        }
    }
    return CRYPT_SUCCESS;
}

int32_t MLKEM_DecodeEk(CRYPT_ML_KEM_Ctx *ctx, const uint8_t *ek, uint32_t ekLen);

// ==========================================
// 5. 核心函数: MLKEM_DecodeDk
// ==========================================

int32_t MLKEM_DecodeDk(CRYPT_ML_KEM_Ctx *ctx, const uint8_t *dk, uint32_t dkLen)
{
    if (ctx == NULL || dk == NULL) {
        return CRYPT_NULL_INPUT;
    }
    if (ctx->info == NULL) {
        return CRYPT_MLKEM_KEYINFO_NOT_SET;
    }
    // 注意：这里检查的是 decapsKeyLen
    if (ctx->info->decapsKeyLen != dkLen) {
        return CRYPT_MLKEM_KEYLEN_ERROR;
    }
    uint8_t k = ctx->info->k;
    
    // 1. 初始化内存 (matrix, s, e, t)
    if (MLKEM_CreateMatrixBuf(k, &ctx->keyData) != CRYPT_SUCCESS) {
        return BSL_MALLOC_FAIL;
    }

    // 2. 解码向量 S (Private Key Part)
    // offset = 32 * 12 * i = 384 * i
    for (int i = 0; i < k; ++i) {
        if (DecodeBits12(ctx->keyData.vectorS[i], dk + MLKEM_SEED_LEN * MLKEM_BITS_OF_Q * i) != CRYPT_SUCCESS) {
            return CRYPT_MLKEM_DECODE_KEY_OVERFLOW;
        }
    }

    // 3. 解码 EK (Public Key Part)
    // ek 位于 dk 的后半部分，偏移量是 k * 384
    const uint8_t *ekBuff = dk + MLKEM_SEED_LEN * MLKEM_BITS_OF_Q * k;
    
    // 复用 MLKEM_DecodeEk 解析 A 和 t
    int32_t ret = MLKEM_DecodeEk(ctx, ekBuff, ctx->info->encapsKeyLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    return CRYPT_SUCCESS;
}