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
int16_t *PRE_COMPUT_TABLE_NTT_MONT = 0; 
// 声明为 extern，并且绝对不要赋值！
// extern int16_t *PRE_COMPUT_TABLE_NTT_MONT;

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

/// [新增] 在 sample_eta.c 中添加

// 1. 定义一个全局缓冲区，SAW 将把符号变量 rand_rows 写入这里
// 大小计算：MLKEM_K_MAX * MLKEM_PRF_BLOCKSIZE * MLKEM_ETA1_MAX
// 4 * 64 * 3 = 768 字节足够了，这里给 1024 安全
uint8_t MOCK_PRF_DATA[1024]; 

// 2. 实现 Mock PRF
// 逻辑：根据 nonce (输入种子的最后一个字节) 决定从缓冲区的哪个位置读取数据
int32_t PRF(void *ctx, const uint8_t *in, size_t inlen, uint8_t *out, size_t outlen) {
    // 种子 q 的结构是: seed (32 bytes) || nonce (1 byte)
    // 所以 nonce 在 in[inlen - 1]
    uint8_t nonce = in[inlen - 1];
    
    // 计算偏移量：每个 nonce 对应一块随机数
    // 假设每次取的数据量是固定的 (MLKEM_PRF_BLOCKSIZE * eta1 = 128 bytes)
    // 注意：这里需要与 SAW 脚本中的布局保持一致
    size_t offset = nonce * outlen; 
    
    if (offset + outlen > sizeof(MOCK_PRF_DATA)) {
        return -1; // 越界保护
    }

    // 模拟生成随机数：直接从全局缓冲区拷贝
    for(size_t i = 0; i < outlen; i++) {
        out[i] = MOCK_PRF_DATA[offset + i];
    }

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