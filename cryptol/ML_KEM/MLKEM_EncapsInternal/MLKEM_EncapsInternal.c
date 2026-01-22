#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
// #include <stdlib.h>
// #include <string.h>

#define MLKEM_N           256
#define MLKEM_K_MAX       4

// Lengths
#define MLKEM_SEED_LEN              32
#define MLKEM_SHARED_KEY_LEN        32
#define CRYPT_SHA3_256_DIGESTSIZE   32
#define CRYPT_SHA3_512_DIGESTSIZE   64

// Error Codes
#define CRYPT_SUCCESS     0
#define CRYPT_ERROR       -1
#define BSL_MALLOC_FAIL   -1004
#define CRYPT_SECUREC_FAIL -1005

// Macros
#define RETURN_RET_IF(cond, val) if(cond) { return val; }
#define EOK 0

// Mock Functions
#define BSL_ERR_PUSH_ERROR(code)

// 定义引用计数类型占位符
typedef uint32_t BSL_SAL_RefCount;

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

typedef struct CryptMlKemCtx CRYPT_ML_KEM_Ctx;

// 模拟 memcpy_s
int memcpy_s(void *dest, size_t destMax, const void *src, size_t count) {
    if (dest == NULL || src == NULL || destMax < count) return CRYPT_SECUREC_FAIL;
    memcpy(dest, src, count);
    return EOK;
}

// 模拟 Cleanse (清空内存)
void BSL_SAL_CleanseData(void *addr, size_t len) {
    if (addr) memset(addr, 0, len);
}

// Hash Functions (Cryptol 模型会覆盖这些函数)
int32_t HashFuncH(void *libCtx, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t outLen);
int32_t HashFuncG(void *libCtx, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t outLen);

// PkeEncrypt 声明
int32_t PkeEncrypt(CRYPT_ML_KEM_Ctx *ctx, uint8_t *ct, uint8_t *m, uint8_t *r);


// NIST.FIPS.203 Algorithm 17 ML-KEM.Encaps_internal(ek, m)
int32_t MLKEM_EncapsInternal(CRYPT_ML_KEM_Ctx *ctx, uint8_t *ct, uint32_t *ctLen, uint8_t *sk, uint32_t *skLen,
    uint8_t *m)
{
    // mhek stores: m || H(ek)
    uint8_t mhek[MLKEM_SEED_LEN + CRYPT_SHA3_256_DIGESTSIZE];
    
    // kr stores: K || r (Output of G)
    uint8_t kr[CRYPT_SHA3_512_DIGESTSIZE];

    // 1. mhek = m || H(ek)
    // Copy m to beginning of buffer
    (void)memcpy_s(mhek, MLKEM_SEED_LEN, m, MLKEM_SEED_LEN);
    
    // Compute H(ek) and write to mhek + 32
    int32_t ret = HashFuncH(ctx->libCtx, ctx->ek, ctx->ekLen, mhek + MLKEM_SEED_LEN, CRYPT_SHA3_256_DIGESTSIZE);
    RETURN_RET_IF(ret != CRYPT_SUCCESS, ret);

    // 2. (K, r) = G(m || H(ek))
    // Input is mhek (64 bytes), Output is kr (64 bytes)
    ret = HashFuncG(ctx->libCtx, mhek, MLKEM_SEED_LEN + CRYPT_SHA3_256_DIGESTSIZE, kr, CRYPT_SHA3_512_DIGESTSIZE);
    RETURN_RET_IF(ret != CRYPT_SUCCESS, ret);

    // 3. Copy Shared Secret K to sk
    // K is the first 32 bytes of kr
    (void)memcpy_s(sk, *skLen, kr, MLKEM_SHARED_KEY_LEN);

    // 4. c <- K-PKE.Encrypt(ek, m, r)
    // Note: r is the second half of kr (kr + 32)
    ret = PkeEncrypt(ctx, ct, m, kr + MLKEM_SHARED_KEY_LEN);
    
    // Cleanse sensitive data kr (Security best practice)
    BSL_SAL_CleanseData(kr, CRYPT_SHA3_512_DIGESTSIZE);
    RETURN_RET_IF(ret != CRYPT_SUCCESS, ret);

    // Set lengths
    *ctLen = ctx->info->cipherLen;
    *skLen = ctx->info->sharedLen;
    
    return CRYPT_SUCCESS;
}