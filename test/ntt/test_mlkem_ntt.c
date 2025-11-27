#include <stdint.h>
#include <stdio.h>

#define MLKEM_N        256
#define MLKEM_N_HALF   128
#define MLKEM_Q        3329
#define MLKEM_Q_INV_BETA (-3327)

// psi 表：bit-reversed 顺序
static const int16_t PRE_COMPUT_TABLE_NTT[MLKEM_N_HALF] = {
    -1044, -758,  -359,  -1517, 1493,  1422,  287,   202,   -171,  622,  1577,  182,   962,   -1202, -1474, 1468,
    573,   -1325, 264,   383,   -829,  1458,  -1602, -130,  -681,  1017, 732,   608,   -1542, 411,   -205,  -1571,
    1223,  652,   -552,  1015,  -1293, 1491,  -282,  -1544, 516,   -8,   -320,  -666,  -1618, -1162, 126,   1469,
    -853,  -90,   -271,  830,   107,   -1421, -247,  -951,  -398,  961,  -1508, -725,  448,   -1065, 677,   -1275,
    -1103, 430,   555,   843,   -1251, 871,   1550,  105,   422,   587,  177,   -235,  -291,  -460,  1574,  1653,
    -246,  778,   1159,  -147,  -777,  1483,  -602,  1119,  -1590, 644,  -872,  349,   418,   329,   -156,  -75,
    817,   1097,  603,   610,   1322,  -1285, -1465, 384,   -1215, -136, 1218,  -1335, -874,  220,   -1187, -1659,
    -1185, -1530, -1278, 794,   -1510, -854,  -870,  478,   -108,  -308, 996,   991,   958,   -1460, 1522,  1628};

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
