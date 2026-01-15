#include <stdint.h>
#include <stdbool.h>

#define MLKEM_N 256
#define MLKEM_N_HALF 128
#define MLKEM_SEED_LEN 32
#define MLKEM_K_MAX 4
#define CRYPT_SHA3_512_DIGESTSIZE 64
#define MLKEM_BITS_OF_Q 12

// 错误码
#define CRYPT_SUCCESS 0
#define CRYPT_ERROR -1

// 错误处理宏
#define RETURN_RET_IF(cond, val) \
    if (cond)                    \
    {                            \
        return val;              \
    }
#define GOTO_ERR_IF(cond, val) \
    if (cond)                  \
    {                          \
        ret = val;             \
        goto ERR;              \
    }
#define MLKEM_CIPHER_LEN 384

// 9 = 8.38 = (((MLKEM_BITS_OF_Q * (MLKEM_N/8) * 2^MLKEM_BITS_OF_Q) / MLKEM_Q) + 64) / 64;
// array_B_arbitrary_length = 9 * 64 + 2 = 578
#define MLKEM_XOF_OUTPUT_LENGTH 578

#define MLKEM_Q 3329
#define MLKEM_Q_INV_BETA (-3327) //(-MLKEM_Q) ^{-1} mod BETA, BETA = 2^{16}
#define MLKEM_Q_HALF ((MLKEM_Q + 1) / 2)
#define MLKEM_INVN 3303 // MLKEM_N_HALF * MLKEM_INVN = 1 mod MLKEM_Q
// MLKEM_BITS_OF_Q and MLKEM_K_MAX are defined earlier to avoid duplication
typedef int32_t (*MlKemHashFunc)(uint32_t id, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t *outLen);
int16_t PRE_COMPUT_TABLE_NTT[MLKEM_N_HALF] = {
    1, 1729, 2580, 3289, 2642, 630, 1897, 848, 1062, 1919, 193, 797, 2786, 3260, 569, 1746, 296, 2447, 1339, 1476,
    3046, 56, 2240, 1333, 1426, 2094, 535, 2882, 2393, 2879, 1974, 821, 289, 331, 3253, 1756, 1197, 2304, 2277, 2055,
    650, 1977, 2513, 632, 2865, 33, 1320, 1915, 2319, 1435, 807, 452, 1438, 2868, 1534, 2402, 2647, 2617, 1481, 648,
    2474, 3110, 1227, 910, 17, 2761, 583, 2649, 1637, 723, 2288, 1100, 1409, 2662, 3281, 233, 756, 2156, 3015, 3050,
    1703, 1651, 2789, 1789, 1847, 952, 1461, 2687, 939, 2308, 2437, 2388, 733, 2337, 268, 641, 1584, 2298, 2037, 3220,
    375, 2549, 2090, 1645, 1063, 319, 2773, 757, 2099, 561, 2466, 2594, 2804, 1092, 403, 1026, 1143, 2150, 2775, 886,
    1722, 1212, 1874, 1029, 2110, 2935, 885, 2154};

typedef struct
{
    int16_t *bufAddr;
    int16_t *matrix[MLKEM_K_MAX][MLKEM_K_MAX];
    int16_t *vectorS[MLKEM_K_MAX];
    int16_t *vectorE[MLKEM_K_MAX];
    int16_t *vectorT[MLKEM_K_MAX];
} MLKEM_MatrixSt;

typedef struct
{
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

struct CryptMlKemCtx
{
    int32_t algId;
    const CRYPT_MlKemInfo *info;
    uint8_t *ek;
    uint32_t ekLen;
    uint8_t *dk;
    uint32_t dkLen;
    // BSL_SAL_RefCount references;
    void *libCtx;
    MLKEM_MatrixSt keyData;
};

typedef struct CryptMlKemCtx CRYPT_ML_KEM_Ctx;
void ByteEncode(uint8_t *r, int16_t *polyF, uint8_t bit);
void memcpy_s(void *dest, size_t destSize, const void *src, size_t count);
void MLKEM_MatrixMulAdd(uint8_t k, int16_t **matrix, int16_t **polyVec, int16_t **polyVecOut, const int16_t *factor);

int32_t SampleEta1(const CRYPT_ML_KEM_Ctx *ctx, uint8_t *digest, int16_t *polyS[], uint8_t *nonce);

int32_t GenMatrix(const CRYPT_ML_KEM_Ctx *ctx, const uint8_t *digest,
                  int16_t *polyMatrix[MLKEM_K_MAX][MLKEM_K_MAX], bool isEnc);

int32_t HashFuncG(void *libCtx, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t outLen);

int32_t PkeKeyGen(CRYPT_ML_KEM_Ctx *ctx, uint8_t *pk, uint8_t *dk, uint8_t *d)
{
    uint8_t k = ctx->info->k;
    uint8_t nonce = 0;
    uint8_t seed[MLKEM_SEED_LEN + 1] = {0}; // Reserved lengths of k is 1 byte.
    uint8_t digest[CRYPT_SHA3_512_DIGESTSIZE] = {0};

    // (p,q) = G(d || k)
    (void)memcpy_s(seed, MLKEM_SEED_LEN + 1, d, MLKEM_SEED_LEN);
    seed[MLKEM_SEED_LEN] = k;
    int32_t ret = HashFuncG(ctx->libCtx, seed, MLKEM_SEED_LEN + 1, digest, CRYPT_SHA3_512_DIGESTSIZE); // Step 1
    RETURN_RET_IF(ret != 0, ret);

    // expand 32+1 bytes to two pseudorandom 32-byte seeds
    uint8_t *p = digest;
    uint8_t *q = digest + CRYPT_SHA3_512_DIGESTSIZE / 2;
    RETURN_RET_IF(ret != 0, ret);

    GOTO_ERR_IF(GenMatrix(ctx, p, ctx->keyData.matrix, false), ret);    // Step 3 - 7
    GOTO_ERR_IF(SampleEta1(ctx, q, ctx->keyData.vectorS, &nonce), ret); // Step 8 - 11
    GOTO_ERR_IF(SampleEta1(ctx, q, ctx->keyData.vectorT, &nonce), ret); // Step 12 - 15
    MLKEM_MatrixMulAdd(k, (int16_t **)ctx->keyData.matrix, ctx->keyData.vectorS, ctx->keyData.vectorT,
                       PRE_COMPUT_TABLE_NTT);
    // output: pk, dk,  ekPKE ← ByteEncode12(𝐭)‖p.
    for (uint8_t i = 0; i < k; i++)
    {
        // Step 19
        ByteEncode(pk + MLKEM_SEED_LEN * MLKEM_BITS_OF_Q * i, ctx->keyData.vectorT[i], MLKEM_BITS_OF_Q);
        // Step 20
        ByteEncode(dk + MLKEM_SEED_LEN * MLKEM_BITS_OF_Q * i, ctx->keyData.vectorS[i], MLKEM_BITS_OF_Q);
    }
    // The buffer of pk is sufficient, check it before calling this function.
    (void)memcpy_s(pk + MLKEM_SEED_LEN * MLKEM_BITS_OF_Q * k, MLKEM_SEED_LEN, p, MLKEM_SEED_LEN);

ERR:
    return ret;
}
