#include <stdint.h>
#include <stddef.h>

#define MLKEM_Q 3329

typedef struct {
    uint64_t barrettMultiplier;  /* round(2 ^ barrettShift / MLKEM_Q) */
    uint16_t barrettShift;
    uint16_t halfQ;              /* rounded (MLKEM_Q / 2) down or up */
    uint8_t  bits;
} MLKEM_BARRET_REDUCE;

static const MLKEM_BARRET_REDUCE MLKEM_BARRETT_TABLE[] = {
    {80635,   28, 1665, 1},
    {1290167, 32, 1665, 10},
    {80635,   28, 1665, 4},
    {40318,   27, 1664, 5},
    {645084,  31, 1664, 11}
};

static int16_t DivMlKemQ(uint16_t x, uint8_t bits, uint16_t halfQ, uint16_t barrettShift, uint64_t barrettMultiplier)
{
    uint64_t round = ((uint64_t)x << bits) + halfQ;
    round *= barrettMultiplier;
    round >>= barrettShift;
    return (int16_t)(round & ((1 << bits) - 1));
}

int16_t Compress(int16_t x, uint8_t d)
{
    int16_t value = 0;
    uint16_t t = x + ((x >> 15) & MLKEM_Q);
    for (size_t i = 0; i < sizeof(MLKEM_BARRETT_TABLE) / sizeof(MLKEM_BARRET_REDUCE); i++) {
        if (d == MLKEM_BARRETT_TABLE[i].bits) {
            value = DivMlKemQ(t,
                MLKEM_BARRETT_TABLE[i].bits,
                MLKEM_BARRETT_TABLE[i].halfQ,
                MLKEM_BARRETT_TABLE[i].barrettShift,
                MLKEM_BARRETT_TABLE[i].barrettMultiplier);
            break;
        }
    }
    return value;
}

int16_t DeCompress(int16_t x, uint8_t bits)
{
    uint32_t product = (uint32_t)x * MLKEM_Q;
    uint32_t power = 1 << bits;
    return (int16_t)((product >> bits) + ((product & (power - 1)) >> (bits - 1)));
}
