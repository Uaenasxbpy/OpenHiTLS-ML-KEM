#include <stdint.h>

#define MLKEM_N      256
#define MLKEM_N_HALF 128
#define MLKEM_Q      3329
#define MLKEM_Q_INV_BETA (-3327)

static inline int16_t BarrettReduction(int16_t a) {
    const int16_t v = ((1 << 26) + MLKEM_Q / 2) / MLKEM_Q;
    int16_t t = ((int32_t)v * a + (1 << 25)) >> 26;
    t *= MLKEM_Q;
    return a - t;
}

static inline int16_t MontgomeryReduction(int32_t a) {
    int16_t t = (int16_t)a * MLKEM_Q_INV_BETA;
    t = (a - (int32_t)t * MLKEM_Q) >> 16;
    return t;
}

void MLKEM_ComputNTT(int16_t *a, const int16_t *psi) {
    uint32_t start = 0;
    uint32_t j = 0;
    uint32_t k = 1;
    int16_t zeta;
    for (uint32_t len = MLKEM_N_HALF; len >= 2; len >>= 1) {
        for (start = 0; start < MLKEM_N; start = j + len) {
            zeta = psi[k++];
            for (j = start; j < start + len; ++j) {
                int16_t t = MontgomeryReduction(a[j + len] * zeta);
                a[j + len] = a[j] - t;
                a[j] += t;
            }
        }
    }
    for (int32_t i = 0; i < MLKEM_N; ++i) {
        a[i] = BarrettReduction(a[i]);
    }
}
// clang -O0 -g -emit-llvm -c mlkem_ntt.c -o mlkem_ntt.bc