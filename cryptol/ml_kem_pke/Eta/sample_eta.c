#include <stdint.h>
// 不再包含 <string.h>

// ==========================================
// 1. 宏定义
// ==========================================
#define MLKEM_N 256
#define MLKEM_SEED_LEN 32
#define MLKEM_PRF_BLOCKSIZE 64
#define MLKEM_ETA1_MAX 3 
#define MLKEM_ETA2_MAX 2
#define CRYPT_SUCCESS 0

// ==========================================
// 2. 结构体定义
// ==========================================
typedef struct {
    uint8_t k;
    uint8_t eta1;
    uint8_t eta2;
} MLKEM_Info;

typedef struct {
    void *libCtx; 
    MLKEM_Info *info;
} CRYPT_ML_KEM_Ctx;

// 全局指针定义 (给 SAW 挂载用)
// int16_t *PRE_COMPUT_TABLE_NTT_MONT = 0; 
// 声明为 extern，并且绝对不要赋值！
extern int16_t *PRE_COMPUT_TABLE_NTT_MONT;

// ==========================================
// 3. 辅助工具：手写内存拷贝
// ==========================================
// 简单的字节拷贝，替代 memcpy
static void simple_memcpy(uint8_t *dst, const uint8_t *src, int32_t len) {
    for (int32_t i = 0; i < len; i++) {
        dst[i] = src[i];
    }
}

// ==========================================
// 4. 外部函数声明 (SAW 会 verify 或 assume 它们)
// ==========================================
void MLKEM_SamplePolyCBD(int16_t *polyF, const uint8_t *buf, uint8_t eta);
void MLKEM_ComputNTT(int16_t *a, const int16_t *psi);

// ==========================================
// 5. Mock PRF (打桩函数)
// ==========================================

// 定义全局缓冲区，SAW 往这里填符号数据
// 4行，每行192字节 (足够容纳 64 * 3)
uint8_t MOCK_PRF_SOURCE[4][192]; 
int32_t mock_call_count = 0;

int32_t PRF(void *ctx, uint8_t *key, int key_len, uint8_t *out, int out_len)
{
    // 简单的越界保护
    if (mock_call_count >= 4) return -1;
    
    // 使用手写的拷贝函数
    // 从全局符号数组 MOCK_PRF_SOURCE 读取数据填入 out
    simple_memcpy(out, MOCK_PRF_SOURCE[mock_call_count], out_len);
    
    mock_call_count++;
    return CRYPT_SUCCESS;
}

// ==========================================
// 6. 待验证的主函数
// ==========================================

int32_t SampleEta1(const CRYPT_ML_KEM_Ctx *ctx, uint8_t *digest, int16_t *polyS[], uint8_t *nonce)
{
    // 初始化缓冲区
    uint8_t q[MLKEM_SEED_LEN + 1];
    // 手动清零 (或者让 SAW 认为它是未初始化的符号值，这里为了严谨简单的初始化一下)
    for(int i=0; i<MLKEM_SEED_LEN+1; i++) q[i] = 0;

    uint8_t prfOut[MLKEM_PRF_BLOCKSIZE * MLKEM_ETA1_MAX];
    for(int i=0; i<MLKEM_PRF_BLOCKSIZE * MLKEM_ETA1_MAX; i++) prfOut[i] = 0;

    // 1. 拷贝种子 (替代 memcpy_s)
    simple_memcpy(q, digest, MLKEM_SEED_LEN);

    for (uint8_t i = 0; i < ctx->info->k; i++) {
        q[MLKEM_SEED_LEN] = *nonce;
        
        // 调用 Mock PRF
        int32_t ret = PRF(ctx->libCtx, q, MLKEM_SEED_LEN + 1, prfOut, MLKEM_PRF_BLOCKSIZE * ctx->info->eta1);
        if (ret != CRYPT_SUCCESS) return ret;
        
        // 调用子函数 (SAW 中会被 Override)
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
    
    simple_memcpy(q, digest, MLKEM_SEED_LEN);

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