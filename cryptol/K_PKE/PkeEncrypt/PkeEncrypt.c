#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define MLKEM_N           256
#define MLKEM_K_MAX       4
#define MLKEM_Q           3329

#define MLKEM_SEED_LEN    32
#define MLKEM_PRF_BLOCKSIZE 64
#define MLKEM_ENCODE_BLOCKSIZE 32
#define MLKEM_ETA1_MAX    3 // Eta1 取值范围通常是 2 或 3

#define CRYPT_SUCCESS     0
#define CRYPT_ERROR       -1
#define BSL_MALLOC_FAIL   -1004

#define RETURN_RET_IF(cond, val) if(cond) { return val; }
#define GOTO_ERR_IF(cond, val)   if(cond) { ret = val; goto ERR; }

#define BSL_SAL_Calloc(num, size) calloc(num, size)
#define BSL_SAL_Free(ptr)         free(ptr)
void memcpy_s(void *dest, size_t destSize, const void *src, size_t count);

int16_t PRE_COMPUT_TABLE_NTT[128] = {0};
int16_t PRE_COMPUT_TABLE_NTT_MONT[128] = {0};

typedef struct {
    int16_t *bufAddr;
    int16_t *matrix[MLKEM_K_MAX][MLKEM_K_MAX];
    int16_t *vectorS[MLKEM_K_MAX]; // KeyGen s
    int16_t *vectorE[MLKEM_K_MAX]; // KeyGen e
    int16_t *vectorT[MLKEM_K_MAX]; // KeyGen t (Public Key Part)
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
    uint8_t *ek; // 公钥
    uint32_t ekLen;
    uint8_t *dk; // 私钥
    uint32_t dkLen;
    void *libCtx;
    MLKEM_MatrixSt keyData; // 包含已解码的 A 和 t
} CRYPT_ML_KEM_Ctx;

int32_t SampleEta1(const CRYPT_ML_KEM_Ctx *ctx, const uint8_t *seed, int16_t *polyVec[], uint8_t *nonce);
int32_t SampleEta2(const CRYPT_ML_KEM_Ctx *ctx, const uint8_t *seed, int16_t *polyVec[], uint8_t *nonce);
void MLKEM_SamplePolyCBD(int16_t *poly, const uint8_t *buf, uint8_t eta);

// PRF
int32_t PRF(void *libCtx, const uint8_t *key, uint32_t keyLen, uint8_t *out, uint32_t outLen);

// u = A^T * y
void MLKEM_TransposeMatrixMulAdd(uint8_t k, int16_t **matrix, int16_t **polyVecIn, int16_t **polyVecOut, const int16_t *factor);
// v = t^T * y
void MLKEM_VectorInnerProductAdd(uint8_t k, int16_t **polyVec1, int16_t **polyVec2, int16_t *polyOut, const int16_t *factor);
// INTT (逆数论变换)
void MLKEM_ComputINTT(int16_t *poly, const int16_t *table);

// 压缩/解压缩
int16_t Compress(int16_t x, uint8_t d);
int16_t DeCompress(int16_t x, uint8_t d);

// 编解码
void ByteEncode(uint8_t *r, int16_t *polyF, uint8_t bit);
void ByteDecode(int16_t *polyF, const uint8_t *r, uint8_t bit);

int32_t PkeEncrypt(CRYPT_ML_KEM_Ctx *ctx, uint8_t *ct, uint8_t *m, uint8_t *r)
{
    uint8_t i;
    uint32_t n;
    uint8_t k = ctx->info->k;
    uint8_t nonce = 0; // Step 1
    uint8_t seedE[MLKEM_SEED_LEN + 1];
    uint8_t bufEncE[MLKEM_PRF_BLOCKSIZE * MLKEM_ETA1_MAX]; // 注意: 这里的大小可能需要根据 eta2 调整
    
    int16_t polyE2[MLKEM_N] = { 0 };
    int16_t polyC2[MLKEM_N] = { 0 }; // v
    int16_t polyM[MLKEM_N] = { 0 };
    
    int16_t *polyVecY[MLKEM_K_MAX] = { 0 };
    int16_t *polyVecE1[MLKEM_K_MAX] = { 0 };
    int16_t *polyVecU[MLKEM_K_MAX] = { 0 }; // u
    
    int16_t *tmpPolyVec = (int16_t *)BSL_SAL_Calloc(MLKEM_N * k * 3, sizeof(int16_t));
    if (tmpPolyVec == NULL) {
        return BSL_MALLOC_FAIL;
    }
    
    // Reference the memory
    for (i = 0; i < k; ++i) {
        polyVecY[i] = tmpPolyVec + MLKEM_N * i;
        polyVecE1[i] = polyVecY[i] + k * MLKEM_N;
        polyVecU[i] = polyVecE1[i] + k * MLKEM_N;
    }
    int32_t ret = 0;
    
    // Step 9-12: Sample y (nonce: 0 -> k-1)
    GOTO_ERR_IF(SampleEta1(ctx, r, polyVecY, &nonce), ret); 
    
    // Step 13-16: Sample e1 (nonce: k -> 2k-1)
    GOTO_ERR_IF(SampleEta2(ctx, r, polyVecE1, &nonce), ret); 

    // Step 17: Sample e2 (nonce: 2k)
    (void)memcpy_s(seedE, MLKEM_SEED_LEN, r, MLKEM_SEED_LEN);
    seedE[MLKEM_SEED_LEN] = nonce; // nonce is now 2k
    GOTO_ERR_IF(PRF(ctx->libCtx, seedE, MLKEM_SEED_LEN + 1, bufEncE, MLKEM_PRF_BLOCKSIZE * ctx->info->eta2), ret);
    MLKEM_SamplePolyCBD(polyE2, bufEncE, ctx->info->eta2);
    
    // Step 18: u = A^T * y
    // 注意：TransposeMatrixMulAdd 使用 ctx->keyData.matrix (即 A)
    MLKEM_TransposeMatrixMulAdd(k, (int16_t **)ctx->keyData.matrix, polyVecY, polyVecU, PRE_COMPUT_TABLE_NTT);
    
    // Step 19: u = INTT(u) + e1, then Compress
    for (i = 0; i < k; i++) {
        MLKEM_ComputINTT(polyVecU[i], PRE_COMPUT_TABLE_NTT_MONT);
        for (n = 0; n < MLKEM_N; n++) {
            // Compress_du(u + e1)
            polyVecU[i][n] = Compress(polyVecU[i][n] + polyVecE1[i][n], ctx->info->du);
        }
    }
    
    // Step 21: v = t^T * y
    MLKEM_VectorInnerProductAdd(k, ctx->keyData.vectorT, polyVecY, polyC2, PRE_COMPUT_TABLE_NTT);
    
    // Decode Message m -> polynomial
    ByteDecode(polyM, m, 1);
    
    // v = INTT(v)
    MLKEM_ComputINTT(polyC2, PRE_COMPUT_TABLE_NTT_MONT);

    // Step 20 & 22: v = Compress_dv(v + e2 + Decompress(m))
    for (n = 0; n < MLKEM_N; n++) {
        polyM[n] = DeCompress(polyM[n], 1); // 1-bit decompress
        polyC2[n] = Compress(polyC2[n] + polyE2[n] + polyM[n], ctx->info->dv);
    }

    // Step 22: Encode u
    for (i = 0; i < k; i++) {
        ByteEncode(ct + MLKEM_ENCODE_BLOCKSIZE * ctx->info->du * i, polyVecU[i], ctx->info->du);
    }
    // Step 23: Encode v
    ByteEncode(ct + MLKEM_ENCODE_BLOCKSIZE * ctx->info->du * k, polyC2, ctx->info->dv);

ERR:
    BSL_SAL_Free(tmpPolyVec);
    return ret;
}

// Stub for memcpy_s
void memcpy_s(void *dest, size_t destSize, const void *src, size_t count) {
    memcpy(dest, src, count);
}