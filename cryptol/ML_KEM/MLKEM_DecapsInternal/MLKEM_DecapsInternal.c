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
#define MLKEM_CIPHER_LEN            384 
#define CRYPT_SHA3_256_DIGESTSIZE   32
#define CRYPT_SHA3_512_DIGESTSIZE   64

// Error Codes
#define CRYPT_SUCCESS               0
#define CRYPT_ERROR                 -1
#define BSL_MALLOC_FAIL             -1004
#define CRYPT_SECUREC_FAIL          -1005
#define CRYPT_MLKEM_INVALID_PRVKEY  -1006

// Macros
#define RETURN_RET_IF(cond, val) if(cond) { return val; }
#define GOTO_ERR_IF(cond, val)   if(cond) { ret = val; goto ERR; }
#define EOK 0

// Mock Functions
#define BSL_ERR_PUSH_ERROR(code)
#define BSL_SAL_Malloc(size)      malloc(size)
#define BSL_SAL_Free(ptr)         free(ptr)

// Reference Count Placeholder
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
    uint32_t encapsKeyLen; // 1184 for 768
    uint32_t decapsKeyLen; // 2400 for 768
    uint32_t cipherLen;    // 1088 for 768
    uint32_t sharedLen;    // 32
    uint32_t bits;
} CRYPT_MlKemInfo;

struct CryptMlKemCtx {
    int32_t algId;
    const CRYPT_MlKemInfo *info;
    uint8_t *ek;
    uint32_t ekLen;
    uint8_t *dk;
    uint32_t dkLen;
    BSL_SAL_RefCount references;
    void *libCtx;
    MLKEM_MatrixSt keyData;
};

typedef struct CryptMlKemCtx CRYPT_ML_KEM_Ctx;

// Memory Ops
int memcpy_s(void *dest, size_t destMax, const void *src, size_t count) {
    if (dest == NULL || src == NULL || destMax < count) return CRYPT_SECUREC_FAIL;
    memcpy(dest, src, count);
    return EOK;
}

void BSL_SAL_CleanseData(void *addr, size_t len) {
    if (addr) memset(addr, 0, len);
}

// Hash Functions
int32_t HashFuncH(void *libCtx, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t outLen);
int32_t HashFuncG(void *libCtx, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t outLen);
int32_t HashFuncJ(void *libCtx, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t outLen);

// PKE Ops
int32_t PkeDecrypt(CRYPT_ML_KEM_Ctx *ctx, uint8_t *m, const uint8_t *ct);
int32_t PkeEncrypt(CRYPT_ML_KEM_Ctx *ctx, uint8_t *ct, uint8_t *m, uint8_t *r);


// NIST.FIPS.203 Algorithm 18 ML-KEM.Decaps_internal(dk, c)
int32_t MLKEM_DecapsInternal(CRYPT_ML_KEM_Ctx *ctx, uint8_t *ct, uint32_t ctLen, uint8_t *sk, uint32_t *skLen)
{
    const CRYPT_MlKemInfo *algInfo = ctx->info;
    
    // Unpack dk (Implicit layout: [dkPKE || ekPKE || h || z])
    // dkPKE length = 384 * k
    // ekPKE length = encapsKeyLen (384 * k + 32)
    // h length = 32
    // z length = 32
    const uint8_t *dk = ctx->dk;                            // Step 1  dkPKE
    const uint8_t *ek = dk + MLKEM_CIPHER_LEN * algInfo->k; // Step 2  ekPKE
    const uint8_t *h = ek + algInfo->encapsKeyLen;          // Step 3  h
    const uint8_t *z = h + MLKEM_SEED_LEN;                  // Step 4  z

    uint8_t mh[MLKEM_SEED_LEN + CRYPT_SHA3_256_DIGESTSIZE]; // m' || h
    uint8_t kr[CRYPT_SHA3_512_DIGESTSIZE];    // K' || r'

    // 1. Re-calculate h = H(ek) and verify against h stored in dk
    // NIST.FIPS.203: test = H(dk[384k : 768k + 32]) and check test == h
    int32_t ret = HashFuncH(ctx->libCtx, ek, algInfo->encapsKeyLen, mh, CRYPT_SHA3_256_DIGESTSIZE);
    RETURN_RET_IF(ret != CRYPT_SUCCESS, ret);
    
    if (memcmp(h, mh, CRYPT_SHA3_256_DIGESTSIZE) != 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_MLKEM_INVALID_PRVKEY);
        return CRYPT_MLKEM_INVALID_PRVKEY;
    }

    // 2. m' = K-PKE.Decrypt(dkPKE, c)
    ret = PkeDecrypt(ctx, mh, ct);  // Result m' stored in first 32 bytes of mh
    RETURN_RET_IF(ret != CRYPT_SUCCESS, ret);

    // 3. (K', r') = G(m' || h)
    // Copy h (from dk) to mh + 32
    (void)memcpy_s(mh + MLKEM_SEED_LEN, CRYPT_SHA3_256_DIGESTSIZE, h, CRYPT_SHA3_256_DIGESTSIZE);
    
    ret = HashFuncG(ctx->libCtx, mh, MLKEM_SEED_LEN + CRYPT_SHA3_256_DIGESTSIZE, kr, CRYPT_SHA3_512_DIGESTSIZE);
    RETURN_RET_IF(ret != CRYPT_SUCCESS, ret);

    // 4. c' = K-PKE.Encrypt(ekPKE, m', r')
    uint8_t *r = kr + MLKEM_SHARED_KEY_LEN;
    uint8_t *newCt = (uint8_t *)BSL_SAL_Malloc(ctLen + MLKEM_SEED_LEN); // +SEED_LEN for J input buffer
    RETURN_RET_IF(newCt == NULL, BSL_MALLOC_FAIL);
    
    GOTO_ERR_IF(PkeEncrypt(ctx, newCt, mh, r), ret);

    // 5. Implicit Rejection Check
    // if c == c': K = K'
    if (memcmp(ct, newCt, ctLen) == 0) {
        (void)memcpy_s(sk, *skLen, kr, MLKEM_SHARED_KEY_LEN);
    } else {
        // else: K = J(z || c)
        // Reuse newCt buffer to construct (z || c)
        (void)memcpy_s(newCt, ctLen + MLKEM_SEED_LEN, z, MLKEM_SEED_LEN);
        (void)memcpy_s(newCt + MLKEM_SEED_LEN, ctLen, ct, ctLen);
        GOTO_ERR_IF(HashFuncJ(ctx->libCtx, newCt, ctLen + MLKEM_SEED_LEN, sk, MLKEM_SHARED_KEY_LEN), ret);
    }
    *skLen = MLKEM_SHARED_KEY_LEN;

ERR:
    BSL_SAL_CleanseData(kr, CRYPT_SHA3_512_DIGESTSIZE);
    BSL_SAL_Free(newCt);
    return ret;
}