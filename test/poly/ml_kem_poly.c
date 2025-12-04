#include <stdint.h>

#define MLKEM_N        256
#define MLKEM_N_HALF   128
#define MLKEM_K_MAX    4
#define MLKEM_Q        3329
#define MLKEM_Q_INV_BETA (-3327)

static inline int16_t BarrettReduction(int16_t a) {
    const int16_t v = ((1 << 26) + MLKEM_Q / 2) / MLKEM_Q;
    int16_t t = ((int32_t)v * a + (1 << 25)) >> 26;
    t *= MLKEM_Q;
    return a - t;
}

// basecase multiplication: add to polyH but not override it
static void BaseMulAdd(int16_t polyH[2], const int16_t f0, const int16_t f1,
                       const int16_t g0, const int16_t g1, const int16_t factor)
{
    polyH[0] += (int16_t)((f0 * g0 + f1 * g1 % MLKEM_Q * factor) % MLKEM_Q);
    polyH[1] += (int16_t)((f0 * g1 + f1 * g0) % MLKEM_Q);
}

static void CircMulAdd(int16_t dest[MLKEM_N], const int16_t src1[MLKEM_N],
                       const int16_t src2[MLKEM_N], const int16_t *factor)
{
    for (uint32_t i = 0; i < MLKEM_N / 4; i++) {
        BaseMulAdd(&dest[4 * i],     src1[4 * i],     src1[4 * i + 1], src2[4 * i],     src2[4 * i + 1], factor[i]);
        BaseMulAdd(&dest[4 * i + 2], src1[4 * i + 2], src1[4 * i + 3], src2[4 * i + 2], src2[4 * i + 3], (int16_t)(-factor[i]));
    }
}

static void PolyReduce(int16_t *poly)
{
    for (int i = 0; i < MLKEM_N; ++i) {
        poly[i] = BarrettReduction(poly[i]);
    }
}

// polyVecOut += (matrix * polyVec): add to polyVecOut but not override it
void MLKEM_MatrixMulAdd(uint8_t k, int16_t **matrix, int16_t **polyVec,
                        int16_t **polyVecOut, const int16_t *factor)
{
    int16_t **currOutPoly = polyVecOut;
    for (int i = 0; i < k; ++i) {
        int16_t **currMatrixPoly = matrix + i * MLKEM_K_MAX;
        int16_t **currVecPoly = polyVec;
        for (int j = 0; j < k; ++j) {
            CircMulAdd(*currOutPoly, *currMatrixPoly, *currVecPoly, factor + MLKEM_N_HALF / 2);
            ++currMatrixPoly;
            ++currVecPoly;
        }
        PolyReduce(*currOutPoly);
        ++currOutPoly;
    }
}

// polyVecOut += (matrix^T * polyVec): add to polyVecOut but not override it
void MLKEM_TransposeMatrixMulAdd(uint8_t k, int16_t **matrix, int16_t **polyVec,
                                 int16_t **polyVecOut, const int16_t *factor)
{
    int16_t **currOutPoly = polyVecOut;
    for (int i = 0; i < k; ++i) {
        int16_t **currMatrixPoly = matrix + i;
        int16_t **currVecPoly = polyVec;
        for (int j = 0; j < k; ++j) {
            CircMulAdd(*currOutPoly, *currMatrixPoly, *currVecPoly, factor + MLKEM_N_HALF / 2);
            currMatrixPoly += MLKEM_K_MAX;
            ++currVecPoly;
        }
        ++currOutPoly;
    }
}

void MLKEM_VectorInnerProductAdd(uint8_t k, int16_t **polyVec1, int16_t **polyVec2,
                                 int16_t *polyOut, const int16_t *factor)
{
    for (int i = 0; i < k; ++i) {
        CircMulAdd(polyOut, polyVec1[i], polyVec2[i], factor + MLKEM_N_HALF / 2);
    }
}

void MLKEM_SamplePolyCBD(int16_t *polyF, uint8_t *buf, uint8_t eta)
{
    uint32_t i, j;
    uint8_t a, b;
    uint32_t t1;
    if (eta == 3) {  // The value of eta can only be 2 or 3.
        for (i = 0; i < MLKEM_N / 4; i++) {
            uint32_t temp = (uint32_t)buf[eta * i];
            temp |= (uint32_t)buf[eta * i + 1] << 8;
            temp |= (uint32_t)buf[eta * i + 2] << 16;
            t1 = temp & 0x00249249;  // extract specific bits
            t1 += (temp >> 1) & 0x00249249;
            t1 += (temp >> 2) & 0x00249249;

            for (j = 0; j < 4; j++) {
                a = (t1 >> (6 * j)) & 0x3;
                b = (t1 >> (6 * j + eta)) & 0x3;
                polyF[4 * i + j] = (int16_t)(a - b);
            }
        }
    } else if (eta == 2) {
        for (i = 0; i < MLKEM_N / 4; i++) {
            uint16_t temp = (uint16_t)buf[eta * i];
            temp |= (uint16_t)buf[eta * i + 1] << 8;
            t1 = temp & 0x5555;  // extract specific bits
            t1 += (temp >> 1) & 0x5555;

            for (j = 0; j < 4; j++) {
                a = (t1 >> (4 * j)) & 0x3;
                b = (t1 >> (4 * j + eta)) & 0x3;
                polyF[4 * i + j] = (int16_t)(a - b);
            }
        }
    }
}

// clang -O0 -g -emit-llvm -c ml_kem_poly.c -o ml_kem_poly.bc
