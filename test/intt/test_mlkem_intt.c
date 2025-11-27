#include <stdint.h>
#include <stdio.h>

#define MLKEM_N        256
#define MLKEM_N_HALF   128
#define MLKEM_Q        3329
#define MLKEM_Q_INV_BETA (-3327)

// ===============================
// psi 表：bit-reversed 顺序
// ===============================
static const int16_t PRE_COMPUT_TABLE_NTT[MLKEM_N_HALF] = {
    -1044, -758,  -359,  -1517, 1493,  1422,  287,   202,   -171,  622,  1577,  182,   962,   -1202, -1474, 1468,
    573,   -1325, 264,   383,   -829,  1458,  -1602, -130,  -681,  1017, 732,   608,   -1542, 411,   -205,  -1571,
    1223,  652,   -552,  1015,  -1293, 1491,  -282,  -1544, 516,   -8,   -320,  -666,  -1618, -1162, 126,   1469,
    -853,  -90,   -271,  830,   107,   -1421, -247,  -951,  -398,  961,  -1508, -725,  448,   -1065, 677,   -1275,
    -1103, 430,   555,   843,   -1251, 871,   1550,  105,   422,   587,  177,   -235,  -291,  -460,  1574,  1653,
    -246,  778,   1159,  -147,  -777,  1483,  -602,  1119,  -1590, 644,  -872,  349,   418,   329,   -156,  -75,
    817,   1097,  603,   610,   1322,  -1285, -1465, 384,   -1215, -136, 1218,  -1335, -874,  220,   -1187, -1659,
    -1185, -1530, -1278, 794,   -1510, -854,  -870,  478,   -108,  -308, 996,   991,   958,   -1460, 1522,  1628};

// ===============================
// BarrettReduction & MontgomeryReduction
// ===============================

// v = floor(2^26 / Q + 1/2) = 20159
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

// ===============================
// NTT 实现
// ===============================
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

// ===============================
// INTT 实现（你的 C 代码）
// ===============================
void MLKEM_ComputINTT(int16_t *a, const int16_t *psi)
{
    int16_t t;
    int16_t zeta;
    uint32_t j = 0;
    const int16_t f = 512; // Mont / 128
    uint32_t k = MLKEM_N_HALF - 1; // 127

    for (uint32_t len = 2; len <= MLKEM_N_HALF; len <<= 1) {
        for (uint32_t start = 0; start < MLKEM_N; start = j + len) {
            zeta = psi[k--];
            for (j = start; j < start + len; j++) {
                t     = a[j];
                a[j]  = BarrettReduction((int16_t)(t + a[j + len]));
                a[j + len] = (int16_t)(a[j + len] - t);
                a[j + len] = MontgomeryReduction((int32_t)zeta * a[j + len]);
            }
        }
    }

    for (j = 0; j < MLKEM_N; j++) {
        a[j] = MontgomeryReduction((int32_t)a[j] * f);
    }
}

// ===============================
// Cryptol-friendly 输出
// ===============================
static void print_as_cryptol_vector(const char *name, const int16_t *a, size_t n)
{
    printf("%s = \n[", name);
    for (size_t i = 0; i < n; i++) {
        printf("0x%04hx", (uint16_t)a[i]);
        if (i + 1 < n) printf(", ");
        if ((i + 1) % 8 == 0 && i + 1 < n) printf("\n ");
    }
    printf("];\n");
}

int main(void)
{
    int16_t a_input[MLKEM_N];
    int16_t a_ntt[MLKEM_N];

    // 固定输入 a[i] = i
    for (int i = 0; i < MLKEM_N; i++) {
        a_input[i] = (int16_t)i;
        a_ntt[i]   = a_input[i];
    }

    // 1) 打印输入
    print_as_cryptol_vector("a_input", a_input, MLKEM_N);

    // 2) NTT
    MLKEM_ComputNTT(a_ntt, PRE_COMPUT_TABLE_NTT);
    print_as_cryptol_vector("a_ntt", a_ntt, MLKEM_N);

    // 3) INTT( a_ntt ) -> a_rec
    MLKEM_ComputINTT(a_ntt, PRE_COMPUT_TABLE_NTT);
    print_as_cryptol_vector("a_intt", a_ntt, MLKEM_N);

    // 简单检查：a_intt 是否恢复为 a_input（模 Q）
    int mismatches = 0;
    for (int i = 0; i < MLKEM_N; i++) {
        int16_t diff = (int16_t)(a_ntt[i] - a_input[i]);
        // 允许模 Q 的等价：diff == 0 or diff == ±Q
        if (!(diff == 0 || diff == MLKEM_Q || diff == -MLKEM_Q)) {
            mismatches++;
        }
    }
    printf("// mismatches (mod Q): %d\n", mismatches);

    return 0;
}
