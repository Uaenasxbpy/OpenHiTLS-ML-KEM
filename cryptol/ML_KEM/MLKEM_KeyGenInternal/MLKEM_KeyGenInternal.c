#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
// #include <stdlib.h>
// #include <string.h>

// ==========================================
// 1. 宏与常量定义
// ==========================================
#define MLKEM_N           256
#define MLKEM_K_MAX       4
#define MLKEM_CIPHER_LEN  384 // 12 bits * 256 / 8

// ML-KEM-768
// ek = 384*3 + 32 = 1184
// dk = 1152 + 1184 + 32 + 32 = 2400
#define MLKEM_SEED_LEN    32
#define CRYPT_SHA3_256_DIGESTSIZE 32

#define CRYPT_SUCCESS     0
#define CRYPT_ERROR       -1
#define BSL_MALLOC_FAIL   -1004
#define CRYPT_SECUREC_FAIL -1005

// 模拟返回值检查宏
#define RETURN_RET_IF(cond, val) if(cond) { return val; }
#define EOK 0

// 模拟 Calloc/Free/Error
#define BSL_SAL_Calloc(num, size) calloc(num, size)
#define BSL_SAL_Free(ptr)         free(ptr)
#define BSL_ERR_PUSH_ERROR(code)  /* printf("Error: %d\n", code) */

// 占位定义引用计数类型 (确保编译通过)
typedef uint32_t BSL_SAL_RefCount;

// ==========================================
// 2. 数据结构 (已更新)
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

struct CryptMlKemCtx {
    int32_t algId;
    const CRYPT_MlKemInfo *info;
    uint8_t *ek;
    uint32_t ekLen;
    uint8_t *dk;
    uint32_t dkLen;
    BSL_SAL_RefCount references; // Added field
    void *libCtx;
    MLKEM_MatrixSt keyData;
};

// 定义 typedef 方便后续使用
typedef struct CryptMlKemCtx CRYPT_ML_KEM_Ctx;

// ==========================================
// 3. 桩函数与依赖声明
// ==========================================

// 模拟 memcpy_s
int memcpy_s(void *dest, size_t destMax, const void *src, size_t count) {
    if (dest == NULL || src == NULL || destMax < count) {
        return CRYPT_SECUREC_FAIL;
    }
    memcpy(dest, src, count);
    return EOK;
}

// 模拟 HashFuncH (SHA3-256)
// SAW 验证时会用 Cryptol 模型覆盖它
int32_t HashFuncH(void *libCtx, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t outLen);

// 声明 PkeKeyGen
int32_t PkeKeyGen(CRYPT_ML_KEM_Ctx *ctx, uint8_t *ek, uint8_t *dk, uint8_t *d);


// ==========================================
// 4. MLKEM_CreateMatrixBuf
// ==========================================

int32_t MLKEM_CreateMatrixBuf(uint8_t k, MLKEM_MatrixSt *st)
{
    // A total of (k * k + 3 * k) data blocks are required. Each block has 512 bytes.
    if (st->bufAddr != NULL) {
        return CRYPT_SUCCESS;
    }
    int16_t *buf = (int16_t *)BSL_SAL_Calloc((k * k + 3 * k) * MLKEM_N, sizeof(int16_t));

    if (buf == NULL) {
        return BSL_MALLOC_FAIL;
    }
    st->bufAddr = buf;  // Used to release memory.
    for (uint8_t i = 0; i < k; i++) {
        for (uint8_t j = 0; j < k; j++) {
            st->matrix[i][j] = buf + (i * k + j) * MLKEM_N;
        }
        // vectorS,vectorE,vectorT use 3 * k data blocks.
        st->vectorS[i] = buf + (k * k + i * 3) * MLKEM_N;
        st->vectorE[i] = buf + (k * k + i * 3 + 1) * MLKEM_N;
        st->vectorT[i] = buf + (k * k + i * 3 + 2) * MLKEM_N;
    }
    return CRYPT_SUCCESS;
}

// ==========================================
// 5. MLKEM_KeyGenInternal (待验证核心)
// ==========================================

// NIST.FIPS.203 Algorithm 16 ML-KEM.KeyGen_internal(d, z)
int32_t MLKEM_KeyGenInternal(CRYPT_ML_KEM_Ctx *ctx, uint8_t *d, uint8_t *z)
{
    const CRYPT_MlKemInfo *algInfo = ctx->info;
    
    // 使用 algInfo 中的参数计算偏移量，或者使用硬编码宏 (需保持一致)
    // 这里使用宏 MLKEM_CIPHER_LEN (384) * k
    uint32_t dkPkeLen = MLKEM_CIPHER_LEN * algInfo->k;
    
    // 1. 初始化矩阵内存
    int32_t ret = MLKEM_CreateMatrixBuf(algInfo->k, &ctx->keyData);
    RETURN_RET_IF(ret != CRYPT_SUCCESS, ret);

    // 2. (ekPKE, dkPKE) <- K-PKE.KeyGen(d)
    ret = PkeKeyGen(ctx, ctx->ek, ctx->dk, d);
    RETURN_RET_IF(ret != CRYPT_SUCCESS, ret);

    // 3. dk <- (dkPKE || ek || H(ek) || z)
    
    // Append ek to dk
    // offset = dkPkeLen
    if (memcpy_s(ctx->dk + dkPkeLen, ctx->dkLen - dkPkeLen, ctx->ek, ctx->ekLen) != EOK) {
        BSL_ERR_PUSH_ERROR(CRYPT_SECUREC_FAIL);
        return CRYPT_SECUREC_FAIL;
    }

    // Append H(ek) to dk
    // offset = dkPkeLen + ekLen
    ret = HashFuncH(ctx->libCtx, ctx->ek, ctx->ekLen, ctx->dk + dkPkeLen + ctx->ekLen, CRYPT_SHA3_256_DIGESTSIZE);
    RETURN_RET_IF(ret != CRYPT_SUCCESS, ret);

    // Append z to dk
    // offset = dkPkeLen + ekLen + 32
    if (memcpy_s(ctx->dk + dkPkeLen + ctx->ekLen + CRYPT_SHA3_256_DIGESTSIZE,
        ctx->dkLen - (dkPkeLen + ctx->ekLen + CRYPT_SHA3_256_DIGESTSIZE), z, MLKEM_SEED_LEN) != EOK) {
        BSL_ERR_PUSH_ERROR(CRYPT_SECUREC_FAIL);
        return CRYPT_SECUREC_FAIL;
    }
    return CRYPT_SUCCESS;
}