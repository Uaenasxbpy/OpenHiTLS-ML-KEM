/* * GenMatrix_Core.c
 * 绝对零依赖版：无 #include，直接定义类型，保证编译通过
 */

// ---------------------------------------------------------
// 1. 手动定义类型 (替代 <stdint.h>)
// ---------------------------------------------------------
typedef unsigned char      uint8_t;
typedef unsigned short     uint16_t;
typedef int                int32_t;
typedef unsigned int       uint32_t;

// ---------------------------------------------------------
// 2. 常量定义
// ---------------------------------------------------------
#define MLKEM_N 256
#define MLKEM_Q 3329
#define MLKEM_SEED_LEN 32
#define MLKEM_XOF_OUTPUT_LENGTH 1000 
#define CRYPT_SUCCESS 0

// ---------------------------------------------------------
// 3. 辅助函数 (替代 <string.h>)
// ---------------------------------------------------------

// 手写一个简单的清零函数，替代 memset
void simple_mem_zero(uint8_t *dst, int32_t n) {
    for (int32_t i = 0; i < n; i++) {
        dst[i] = 0;
    }
}

// ---------------------------------------------------------
// 4. Mock 函数
// ---------------------------------------------------------

// Mock Hash
// 注意：SAW 会 override 这个函数，这里的实现只是为了编译
int32_t HashFuncXOF(void *libCtx, const uint8_t *in, uint32_t inLen, uint8_t *out, uint32_t outLen) {
    if (out) {
        simple_mem_zero(out, outLen);
    }
    return CRYPT_SUCCESS;
}

// Mock Parse
// 注意：SAW 会 override 这个函数
int32_t Parse(uint16_t *polyNtt, uint8_t *arrayB, uint32_t arrayLen, uint32_t n) {
    return CRYPT_SUCCESS;
}

// ---------------------------------------------------------
// 5. 核心逻辑函数 (扁平化版本)
// ---------------------------------------------------------

/**
 * GenMatrix_Core
 * 简化后的核心逻辑验证函数
 * 输入:
 * - k: 参数 (2, 3, 4)
 * - rho: 32字节种子
 * - isEnc: 0 或 1 (替代 bool)
 * - output_flat: 指向 [k * k * 256] 大小的 uint16_t 数组
 */
int32_t GenMatrix_Core(uint8_t k, 
                       const uint8_t *rho, 
                       uint8_t isEnc, 
                       uint16_t *output_flat) 
{
    // 局部变量
    uint8_t p[MLKEM_SEED_LEN + 2];
    uint8_t xofOut[MLKEM_XOF_OUTPUT_LENGTH];

    // 手动复制种子 rho 到 p (替代 memcpy)
    for(int32_t m = 0; m < MLKEM_SEED_LEN; m++) {
        p[m] = rho[m];
    }
    
    // 双重循环
    for (uint8_t i = 0; i < k; i++) {
        for (uint8_t j = 0; j < k; j++) {
            
            // 构造输入种子 (根据 isEnc 决定顺序)
            if (isEnc) {
                p[MLKEM_SEED_LEN] = i;
                p[MLKEM_SEED_LEN + 1] = j;
            } else {
                p[MLKEM_SEED_LEN] = j;
                p[MLKEM_SEED_LEN + 1] = i;
            }
            
            // 调用 Mock Hash
            // 传入 0 作为 libCtx (void*)
            HashFuncXOF(0, p, MLKEM_SEED_LEN + 2, xofOut, MLKEM_XOF_OUTPUT_LENGTH);
            
            // 计算扁平化数组的偏移量
            // 逻辑: offset = (i * k + j) * 256
            // 注意这里要强制转换防溢出，虽然在 SAW 里通常没事
            uint32_t block_idx = (uint32_t)i * k + j;
            uint32_t offset = block_idx * MLKEM_N;
            
            // 调用 Parse，写入到 output_flat 的对应位置
            Parse(&output_flat[offset], xofOut, MLKEM_XOF_OUTPUT_LENGTH, MLKEM_N);
        }
    }
    return CRYPT_SUCCESS;
}