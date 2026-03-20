#include <stdint.h>
#include <stdbool.h>

#define MLKEM_N 256
#define MLKEM_Q 3329
#define MLKEM_K_MAX 4
#define MLKEM_SEED_LEN 32
#define MLKEM_XOF_OUTPUT_LENGTH 578

typedef __SIZE_TYPE__ size_t;

void *memcpy(void *dst, const void *src, size_t n) {
    uint8_t *d = (uint8_t *)dst;
    const uint8_t *s = (const uint8_t *)src;
    while (n--) {
        *d++ = *s++;
    }
    return dst;
}

#define memcpy_s(dest, destsz, src, count) memcpy(dest, src, count)

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
    void *libCtx;
};
typedef struct CryptMlKemCtx CRYPT_ML_KEM_Ctx;

/* 外部 XOF 接口 */
int32_t HashFuncXOF(void *libCtx,
                    const uint8_t *in, uint32_t inLen,
                    uint8_t *out, uint32_t outLen);

/*
 * 只保留 Parse 的核心采样逻辑：
 * - 每 3 字节拆成 2 个 12-bit 候选值
 * - 只收 < MLKEM_Q 的值
 * - 默认假设 xofOut 足够生成 256 个系数
 */
static void Parse(uint16_t polyNtt[MLKEM_N],
                             const uint8_t xofOut[MLKEM_XOF_OUTPUT_LENGTH])
{
    uint32_t i = 0;
    uint32_t j = 0;

    while (j < MLKEM_N) {
        uint16_t d1 = ((uint16_t)xofOut[i])
                    + ((((uint16_t)xofOut[i + 1]) & 0x0f) << 8);

        uint16_t d2 = (((uint16_t)xofOut[i + 1]) >> 4)
                    + (((uint16_t)xofOut[i + 2]) << 4);

        if (d1 < MLKEM_Q) {
            polyNtt[j++] = d1;
        }
        if ((d2 < MLKEM_Q) && (j < MLKEM_N)) {
            polyNtt[j++] = d2;
        }

        i += 3;
    }
}

/*
 * 只保留 GenMatrix 的采样生成矩阵过程：
 * - p = digest || [i,j]    (isEnc = true)
 * - p = digest || [j,i]    (isEnc = false)
 * - xofOut = HashFuncXOF(p)
 * - polyMatrix[i][j] = Parse(xofOut)
 *
 * 不再关心返回错误码；默认 HashFuncXOF 可正常输出。
 */
void GenMatrix(const CRYPT_ML_KEM_Ctx *ctx,
                          const uint8_t digest[MLKEM_SEED_LEN],
                          int16_t *polyMatrix[MLKEM_K_MAX][MLKEM_K_MAX],
                          bool isEnc)
{
    uint8_t k = ctx->info->k;
    uint8_t p[MLKEM_SEED_LEN + 2];
    uint8_t xofOut[MLKEM_XOF_OUTPUT_LENGTH];

    (void)memcpy_s(p, MLKEM_SEED_LEN, digest, MLKEM_SEED_LEN);

    for (uint8_t i = 0; i < k; i++) {
        for (uint8_t j = 0; j < k; j++) {
            if (isEnc) {
                p[MLKEM_SEED_LEN]     = i;
                p[MLKEM_SEED_LEN + 1] = j;
            } else {
                p[MLKEM_SEED_LEN]     = j;
                p[MLKEM_SEED_LEN + 1] = i;
            }

            (void)HashFuncXOF(ctx->libCtx,
                              p, MLKEM_SEED_LEN + 2,
                              xofOut, MLKEM_XOF_OUTPUT_LENGTH);

            Parse((uint16_t *)polyMatrix[i][j], xofOut);
        }
    }
}
void Parse_export(uint16_t polyNtt[MLKEM_N],
                  const uint8_t xofOut[MLKEM_XOF_OUTPUT_LENGTH]) {
    Parse(polyNtt, xofOut);
}

/*
 * 验证专用：直接忽略 HashFuncXOF，把每个位置的 XOF 输出
 * 视为 oracle[i][j] 给定的 578 字节输入流。
 *
 * 这正对应你要验证的“采样生成矩阵过程”：
 *   isEnc = true  -> out[i][j] = Parse(oracle[i][j])
 *   isEnc = false -> out[i][j] = Parse(oracle[j][i])
 */
void GenMatrix_k3_oracle(const uint8_t oracle[3][3][MLKEM_XOF_OUTPUT_LENGTH],
                         int16_t out[3][3][MLKEM_N],
                         bool isEnc)
{
    for (uint8_t i = 0; i < 3; i++) {
        for (uint8_t j = 0; j < 3; j++) {
            const uint8_t *xof = isEnc ? oracle[i][j] : oracle[j][i];
            Parse((uint16_t *)out[i][j], xof);
        }
    }
}