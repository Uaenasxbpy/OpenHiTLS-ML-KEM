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

#define MLKEM_ENCODE_BLOCKSIZE 32

#define CRYPT_SUCCESS     0
#define CRYPT_ERROR       -1
#define BSL_MALLOC_FAIL   -1004

// 模拟 Calloc/Free
#define BSL_SAL_Calloc(num, size) calloc(num, size)
#define BSL_SAL_Free(ptr)         free(ptr)

// NTT 表占位符
int16_t PRE_COMPUT_TABLE_NTT[128] = {0};
int16_t PRE_COMPUT_TABLE_NTT_MONT[128] = {0};

// ==========================================
// 2. 数据结构
// ==========================================
typedef struct {
    int16_t *bufAddr;
    int16_t *matrix[MLKEM_K_MAX][MLKEM_K_MAX];
    int16_t *vectorS[MLKEM_K_MAX]; // Private Key s (NTT domain)
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
// 3. 子函数声明 (SAW 验证时会被 Cryptol 模型替代)
// ==========================================

// 编解码
void ByteEncode(uint8_t *r, int16_t *polyF, uint8_t bit);
void ByteDecode(int16_t *polyF, const uint8_t *a, uint8_t bit);

// 压缩/解压缩
int16_t Compress(int16_t x, uint8_t d);
static int16_t DeCompress(int16_t x, uint8_t bits);

// NTT / INTT
void MLKEM_ComputNTT(int16_t *a, const int16_t *psi);
void MLKEM_ComputINTT(int16_t *a, const int16_t *psi);

// 向量内积: polyOut = polyOut + (vec1 . vec2)
void MLKEM_VectorInnerProductAdd(uint8_t k, int16_t **polyVec1, int16_t **polyVec2, int16_t *polyOut,
                                 const int16_t *factor);

// ==========================================
// 4. 核心函数 PkeDecrypt
// ==========================================

int32_t PkeDecrypt(CRYPT_ML_KEM_Ctx *ctx, uint8_t *result, const uint8_t *ciphertext)
{
    uint8_t i;
    uint8_t k = ctx->info->k;
    uint32_t n;
    
    // Memory Allocation
    // tmpPolyVec = polyM (1) || polyC2 (1) || polyVecC1 (k)
    // Total: k + 2 blocks
    int16_t *tmpPolyVec = (int16_t *)BSL_SAL_Calloc((k * 2 + 1) * MLKEM_N, sizeof(int16_t));
    if (tmpPolyVec == NULL) {
        return BSL_MALLOC_FAIL;
    }
    
    int16_t *polyVecC1[MLKEM_K_MAX];
    int16_t *polyC2;
    int16_t *polyM;
    
    // Reference the stack memory (Pointer arithmetic)
    polyM = tmpPolyVec;                    // Block 0
    polyC2 = tmpPolyVec + MLKEM_N;         // Block 1
    for (i = 0; i < k; ++i) {
        polyVecC1[i] = tmpPolyVec + MLKEM_N * (i + 2); // Block 2..k+1
    }
    
    // 1. Decode & Decompress u (polyVecC1)
    for (i = 0; i < k; i++) {
        // Step 3: Decode ciphertext part 1
        ByteDecode(polyVecC1[i], ciphertext + MLKEM_ENCODE_BLOCKSIZE * ctx->info->du * i, ctx->info->du);
    }
    
    // 2. Decode & Decompress v (polyC2)
    // Step 4: Decode ciphertext part 2
    ByteDecode(polyC2, ciphertext + MLKEM_ENCODE_BLOCKSIZE * ctx->info->du * k, ctx->info->dv);
    
    for (i = 0; i < k; i++) {
        for (n = 0; n < MLKEM_N; n++) {
            // Decompress u
            polyVecC1[i][n] = DeCompress(polyVecC1[i][n], ctx->info->du);
            if (i == 0) {
                // Decompress v (only need to do this once loop)
                polyC2[n] = DeCompress(polyC2[n], ctx->info->dv);
            }
        }
        // Step 5: NTT(u) -> u_hat
        MLKEM_ComputNTT(polyVecC1[i], PRE_COMPUT_TABLE_NTT_MONT);
    }
    
    // 3. Compute s^T * u_hat
    // ctx->keyData.vectorS contains 's' (already in NTT domain from KeyGen/DecodeDk)
    // polyM is initialized to 0 by Calloc, so InnerProductAdd works correctly as (0 + s.u)
    MLKEM_VectorInnerProductAdd(k, ctx->keyData.vectorS, polyVecC1, polyM, PRE_COMPUT_TABLE_NTT);
    
    // 4. INTT to get (s^T * u) in polynomial domain
    MLKEM_ComputINTT(polyM, PRE_COMPUT_TABLE_NTT_MONT);
    
    // 5. Compute w = v - (s^T * u) and Compress(w, 1) to get message m
    for (n = 0; n < MLKEM_N; n++) {
        // polyC2 is v, polyM is s.u
        polyM[n] = Compress(polyC2[n] - polyM[n], 1);
    }

    // 6. Encode message m to bytes
    ByteEncode(result, polyM, 1);  // Step 7
    
    BSL_SAL_Free(tmpPolyVec);
    return CRYPT_SUCCESS;
}