#include <stdint.h>

#define MLKEM_Q 3329u
#define CRYPT_SUCCESS 0
#define CRYPT_MLKEM_KEYLEN_ERROR (-1)
#define BSL_ERR_PUSH_ERROR(code)

#define PARSE_INPUT_LEN 578u
#define PARSE_USABLE_LEN 576u
#define PARSE_CHUNKS 192u
#define PARSE_CANDS 384u
#define PARSE_OUT 256u

static uint16_t Parse_D1(const uint8_t *p)
{
    return (uint16_t)p[0]
         | (uint16_t)(((uint16_t)p[1] & 0x0Fu) << 8);
}

static uint16_t Parse_D2(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[1]) >> 4)
         | (uint16_t)(((uint16_t)p[2]) << 4);
}

/* 选择第 rank 个（从 1 开始计数）有效候选值。
 * prefix[i+1] = prefix[i] + ok[i]
 * 因此当 ok[i] == 1 且 prefix[i+1] == rank 时，cand[i] 就是第 rank 个有效值。
 *
 * 这个函数里虽然有条件判断，但没有符号地址写内存。
 */
static uint16_t SelectByRank(const uint16_t cand[PARSE_CANDS],
                             const uint8_t ok[PARSE_CANDS],
                             const uint16_t prefix[PARSE_CANDS + 1],
                             uint16_t rank)
{
    uint32_t i;
    uint16_t result = 0;

    for (i = 0; i < PARSE_CANDS; ++i) {
        if (ok[i] && prefix[i + 1] == rank) {
            result = cand[i];
        }
    }

    return result;
}

/* 专用于 SAW 验证的固定实例版本：
 * - 输入固定按 578 字节解释
 * - 实际只使用前 576 字节（192 个完整 chunk）
 * - 输出固定为 256 个系数
 */
int32_t Parse(uint16_t *polyNtt, const uint8_t *arrayB)
{
    uint16_t cand[PARSE_CANDS];
    uint8_t ok[PARSE_CANDS];
    uint16_t prefix[PARSE_CANDS + 1];

    uint32_t k;
    uint32_t i;
    uint16_t valid_count;

    /* 第一阶段：固定收集 384 个候选值及其有效标志 */
    for (k = 0; k < PARSE_CHUNKS; ++k) {
        const uint8_t *p = arrayB + 3u * k;
        uint16_t d1 = Parse_D1(p);
        uint16_t d2 = Parse_D2(p);

        cand[2u * k] = d1;
        cand[2u * k + 1u] = d2;

        ok[2u * k] = (uint8_t)(d1 < MLKEM_Q);
        ok[2u * k + 1u] = (uint8_t)(d2 < MLKEM_Q);
    }

    /* 第二阶段：前缀计数 */
    prefix[0] = 0;
    for (i = 0; i < PARSE_CANDS; ++i) {
        prefix[i + 1u] = (uint16_t)(prefix[i] + (uint16_t)ok[i]);
    }

    valid_count = prefix[PARSE_CANDS];

    /* 若有效值不足 256 个，则失败 */
    if (valid_count < PARSE_OUT) {
        BSL_ERR_PUSH_ERROR(CRYPT_MLKEM_KEYLEN_ERROR);
        return CRYPT_MLKEM_KEYLEN_ERROR;
    }

    /* 第三阶段：按固定输出索引生成 polyNtt[0..255] */
    for (i = 0; i < PARSE_OUT; ++i) {
        polyNtt[i] = SelectByRank(cand, ok, prefix, (uint16_t)(i + 1u));
    }

    return CRYPT_SUCCESS;
}