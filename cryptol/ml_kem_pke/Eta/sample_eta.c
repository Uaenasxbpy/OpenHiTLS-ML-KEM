#include <stdint.h>
#define MLKEM_N 256
#define MLKEM_SEED_LEN 32
#define MLKEM_PRF_BLOCKSIZE 64
#define MLKEM_ETA1_MAX 3 
#define MLKEM_ETA2_MAX 2
#define CRYPT_SUCCESS 0
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
    // BSL_SAL_RefCount references;
    void *libCtx;
    // MLKEM_MatrixSt keyData;
};
typedef struct CryptMlKemCtx CRYPT_ML_KEM_Ctx;
int16_t *PRE_COMPUT_TABLE_NTT_MONT = 0; 
void MLKEM_SamplePolyCBD(int16_t *polyF, const uint8_t *buf, uint8_t eta);
void MLKEM_ComputNTT(int16_t *a, const int16_t *psi);
int32_t PRF(void *ctx, const uint8_t *in, size_t inlen, uint8_t *out, size_t outlen);
int32_t SampleEta1(const CRYPT_ML_KEM_Ctx *ctx, uint8_t *digest, int16_t *polyS[], uint8_t *nonce)
{
    uint8_t q[MLKEM_SEED_LEN + 1];
    for(int i=0; i<MLKEM_SEED_LEN+1; i++) q[i] = 0;
    uint8_t prfOut[MLKEM_PRF_BLOCKSIZE * MLKEM_ETA1_MAX];
    for(int i=0; i<MLKEM_PRF_BLOCKSIZE * MLKEM_ETA1_MAX; i++) prfOut[i] = 0;
    // simple_memcpy(q, digest, MLKEM_SEED_LEN);
    for(int j=0; j<MLKEM_SEED_LEN; j++) {
        q[j] = digest[j];
    }
    for (uint8_t i = 0; i < ctx->info->k; i++) {
        q[MLKEM_SEED_LEN] = *nonce;
        int32_t ret = PRF(ctx->libCtx, q, MLKEM_SEED_LEN + 1, prfOut, MLKEM_PRF_BLOCKSIZE * ctx->info->eta1);
        if (ret != CRYPT_SUCCESS) return ret;
        MLKEM_SamplePolyCBD(polyS[i], prfOut, ctx->info->eta1);
        *nonce = *nonce + 1;
        MLKEM_ComputNTT(polyS[i], PRE_COMPUT_TABLE_NTT_MONT);
    }
    return CRYPT_SUCCESS;
}

int32_t SampleEta2(const CRYPT_ML_KEM_Ctx *ctx, uint8_t *digest, int16_t *polyS[], uint8_t *nonce){
    uint8_t q[MLKEM_SEED_LEN + 1];
    for(int i=0; i<MLKEM_SEED_LEN+1; i++) q[i] = 0;
    uint8_t prfOut[MLKEM_PRF_BLOCKSIZE * MLKEM_ETA2_MAX];
    for(int i=0; i<MLKEM_PRF_BLOCKSIZE * MLKEM_ETA2_MAX; i++) prfOut[i] = 0;
    for(int j=0; j<MLKEM_SEED_LEN; j++) {
        q[j] = digest[j];
    }
    for (uint8_t i = 0; i < ctx->info->k; i++) {
        q[MLKEM_SEED_LEN] = *nonce;
        int32_t ret = PRF(ctx->libCtx, q, MLKEM_SEED_LEN + 1, prfOut, MLKEM_PRF_BLOCKSIZE * ctx->info->eta2);
        if (ret != CRYPT_SUCCESS) return ret;
        MLKEM_SamplePolyCBD(polyS[i], prfOut, ctx->info->eta2);
        *nonce = *nonce + 1;
        // Eta2 不需要 NTT
    }
    return CRYPT_SUCCESS;
}

// scp -r "F:\研1\PQC算法验证与优化\Kyber一致性验证\OpenHiTLS-ML-KEM" paper207@10.122.200.71:/home/paper207/Downloads/xiongbing/cryptol/