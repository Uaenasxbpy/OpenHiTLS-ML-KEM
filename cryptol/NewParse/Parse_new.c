/*
 * Parse_new.c
 *
 * 语义保持版、较 SAW-friendly 的 Parse 实现。
 *
 * 说明：
 * 1. 保持原始接口不变，函数名仍叫 Parse，便于直接替换原 bitcode 验证。
 * 2. 主要改动：
 *    - 先按完整 3-byte chunk 数量固定循环；
 *    - 将 d1/d2 的提取拆成纯 helper；
 *    - 将“若合法则追加”拆成单独 helper。
 */

#include <stdint.h>

#define MLKEM_Q 3329u
#define CRYPT_SUCCESS 0
#define CRYPT_MLKEM_KEYLEN_ERROR (-1)
#define BSL_ERR_PUSH_ERROR(code)

/* 从 3-byte chunk 中提取第一个 12-bit 值：
 * d1 = b0 + low4(b1) << 8
 */
static uint16_t Parse_D1(const uint8_t *p)
{
    return (uint16_t)p[0]
         | (uint16_t)(((uint16_t)p[1] & 0x0Fu) << 8);
}

/* 从 3-byte chunk 中提取第二个 12-bit 值：
 * d2 = high4(b1) + b2 << 4
 */
static uint16_t Parse_D2(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[1]) >> 4)
         | (uint16_t)(((uint16_t)p[2]) << 4);
}

/* 若 d < Q 且 j < n，则将 d 写入 polyNtt[j]，并返回 j + 1；
 * 否则返回原 j。
 *
 * 这个 helper 把“条件写入 + 更新计数”的逻辑局部化，
 * 便于后续单独建模和单独证明。
 */
static uint32_t Parse_AppendIfValid(uint16_t *polyNtt,
                                    uint32_t n,
                                    uint32_t j,
                                    uint16_t d)
{
    if (j < n && d < MLKEM_Q) {
        polyNtt[j] = d;
        return j + 1;
    }
    return j;
}

/*
 * Parse: 从字节流中提取 12-bit 值，紧凑写入 polyNtt[]
 *
 * 与原始版本语义等价：
 * - 每轮消耗 3 字节，得到 d1 / d2
 * - d1 < Q 时写入
 * - d2 < Q 且仍需要更多输出时写入
 * - 若完整 chunk 全部处理完后仍未收集到 n 个系数，则返回错误
 *
 * 等价性说明：
 * 原函数在 while (j < n) 中，每次先检查是否还剩至少 3 字节。
 * 这里改为只遍历 full_chunks = arrayLen / 3 个完整 chunk；
 * 若遍历完仍未达到 n，则统一返回 KEYLEN_ERROR。
 * 这与原函数行为一致，包括 arrayLen 不是 3 的倍数的情况。
 */
int32_t Parse(uint16_t *polyNtt, const uint8_t *arrayB, uint32_t arrayLen, uint32_t n)
{
    uint32_t full_chunks = arrayLen / 3u;
    uint32_t k;
    uint32_t j = 0;

    /* 固定按完整 3-byte chunk 推进，而不是让循环退出条件直接依赖 j */
    for (k = 0; k < full_chunks && j < n; ++k) {
        const uint8_t *p = arrayB + 3u * k;
        uint16_t d1 = Parse_D1(p);
        uint16_t d2 = Parse_D2(p);

        j = Parse_AppendIfValid(polyNtt, n, j, d1);
        j = Parse_AppendIfValid(polyNtt, n, j, d2);
    }

    /* 若已收集满 n 个系数，则成功；否则说明输入不足 */
    if (j == n) {
        return CRYPT_SUCCESS;
    }

    BSL_ERR_PUSH_ERROR(CRYPT_MLKEM_KEYLEN_ERROR);
    return CRYPT_MLKEM_KEYLEN_ERROR;
}