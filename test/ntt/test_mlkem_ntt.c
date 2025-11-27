#include <stdint.h>
#include <stdio.h>

#define MLKEM_N        256
#define MLKEM_N_HALF   128
#define MLKEM_Q        3329
#define MLKEM_Q_INV_BETA (-3327)

// psi 表：bit-reversed 顺序
static const int16_t PRE_COMPUT_TABLE_NTT[MLKEM_N_HALF] = {
    1, 1729, 2580, 3289, 2642, 630, 1897, 848, 1062, 1919, 193, 797, 2786, 3260, 569, 1746,
    296, 2447, 1339, 1476, 3046, 56, 2240, 1333, 1426, 2094, 535, 2882, 2393, 2879, 1974, 821,
    289, 331, 3253, 1756, 1197, 2304, 2277, 2055, 650, 1977, 2513, 632, 2865, 33, 1320, 1915,
    2319, 1435, 807, 452, 1438, 2868, 1534, 2402, 2647, 2617, 1481, 648, 2474, 3110, 1227, 910,
    17, 2761, 583, 2649, 1637, 723, 2288, 1100, 1409, 2662, 3281, 233, 756, 2156, 3015, 3050,
    1703, 1651, 2789, 1789, 1847, 952, 1461, 2687, 939, 2308, 2437, 2388, 733, 2337, 268, 641,
    1584, 2298, 2037, 3220, 375, 2549, 2090, 1645, 1063, 319, 2773, 757, 2099, 561, 2466, 2594,
    2804, 1092, 403, 1026, 1143, 2150, 2775, 886, 1722, 1212, 1874, 1029, 2110, 2935, 885, 2154
};

// BarrettReduction & MontgomeryReduction
static inline int16_t BarrettReduction(int16_t a)
{
    const int16_t v = (int16_t)(((1u << 26) + MLKEM_Q / 2) / MLKEM_Q);
    int16_t t = (int16_t)(((int32_t)v * a + (1 << 25)) >> 26);
    t = (int16_t)(t * MLKEM_Q);
    return (int16_t)(a - t);
}

static inline int16_t MontgomeryReduction(int32_t a)
{
    int16_t t = (int16_t)a * MLKEM_Q_INV_BETA;
    t = (int16_t)((a - (int32_t)t * MLKEM_Q) >> 16);
    return t;
}

// NTT
void MLKEM_ComputNTT(int16_t *a, const int16_t *psi)
{
    uint32_t start = 0;
    uint32_t j = 0;
    uint32_t k = 1;
    int16_t zeta;

    for (uint32_t len = MLKEM_N_HALF; len >= 2; len >>= 1) {
        for (start = 0; start < MLKEM_N; start = j + len) {
            zeta = psi[k++];
            for (j = start; j < start + len; ++j) {
                int16_t t = MontgomeryReduction((int32_t)a[j + len] * zeta);
                a[j + len] = (int16_t)(a[j] - t);
                a[j]       = (int16_t)(a[j] + t);
            }
        }
    }

    for (int32_t i = 0; i < (int32_t)MLKEM_N; ++i) {
        a[i] = BarrettReduction(a[i]);
    }
}

// Cryptol-friendly output
static void print_as_cryptol_vector(const char *name, const int16_t *a, size_t n)
{
    printf("%s = [", name);
    for (size_t i = 0; i < n; i++) {
        printf("0x%04hx", (uint16_t)a[i]);
        if (i + 1 < n) printf(", ");
    }
    printf("];\n");
}

int main(void)
{
    int16_t a[MLKEM_N];

    for (int i = 0; i < MLKEM_N; i++) {
        a[i] = (int16_t)i;   // 完全确定，无随机因素
    }

    // 输出输入向量
    print_as_cryptol_vector("a_input", a, MLKEM_N);

    // 调用 NTT
    MLKEM_ComputNTT(a, PRE_COMPUT_TABLE_NTT);

    // 输出结果
    print_as_cryptol_vector("a_output", a, MLKEM_N);

    return 0;
}
