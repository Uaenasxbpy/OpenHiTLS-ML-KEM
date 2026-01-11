#include <stdint.h>

#define MLKEM_N 256

/* * MLKEM_SamplePolyCBD
 * 功能：将字节流转换为多项式系数 (Center Binomial Distribution)
 * 输入：buf (字节流), eta (参数 2 或 3)
 * 输出：polyF (多项式系数数组)
 */
void MLKEM_SamplePolyCBD(int16_t *polyF, const uint8_t *buf, uint8_t eta)
{
    uint32_t i;
    uint32_t j;
    uint8_t a;
    uint8_t b;
    uint32_t t1;

    if (eta == 3) {  // eta = 3 的情况
        for (i = 0; i < MLKEM_N / 4; i++) {
            // 将 3 个字节拼成 24-bit 整数 (小端序)
            uint32_t temp = (uint32_t)buf[3 * i];
            temp |= (uint32_t)buf[3 * i + 1] << 8;
            temp |= (uint32_t)buf[3 * i + 2] << 16;

            // 位操作魔法数字：0x00249249 = Binary ...001001001001
            // 作用：并行计算每 3 个 bit 的汉明重量(Hamming Weight)
            t1 = temp & 0x00249249; 
            t1 += (temp >> 1) & 0x00249249;
            t1 += (temp >> 2) & 0x00249249;

            for (j = 0; j < 4; j++) {
                // 取出计算好的汉明重量，a 和 b
                a = (t1 >> (6 * j)) & 0x3;
                b = (t1 >> (6 * j + 3)) & 0x3;
                // 计算差值
                polyF[4 * i + j] = (int16_t)(a - b);
            }
        }
    } else if (eta == 2) { // eta = 2 的情况
        for (i = 0; i < MLKEM_N / 4; i++) {
            // 将 2 个字节拼成 16-bit 整数
            uint32_t temp = (uint32_t)buf[2 * i];
            temp |= (uint32_t)buf[2 * i + 1] << 8;

            // 魔法数字：0x5555 = Binary ...01010101
            // 作用：并行计算每 2 个 bit 的汉明重量
            t1 = temp & 0x5555;
            t1 += (temp >> 1) & 0x5555;

            for (j = 0; j < 4; j++) {
                a = (t1 >> (4 * j)) & 0x3;
                b = (t1 >> (4 * j + 2)) & 0x3;
                polyF[4 * i + j] = (int16_t)(a - b);
            }
        }
    }
}