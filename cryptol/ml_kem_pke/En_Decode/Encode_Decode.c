/*
 * Encode_Decode.c
 * Standalone compilation unit for ML-KEM Encode/Decode functions.
 * Designed for Formal Verification with SAW.
 */

#include <stdint.h>

// -----------------------------------------------------------------------------
// 1. Constants & Macros Definitions
// -----------------------------------------------------------------------------

#define MLKEM_N 256
#define MLKEM_Q 3329
#define BITS_OF_BYTE 8

// Error Codes
#define CRYPT_SUCCESS 0
#define CRYPT_MLKEM_DECODE_KEY_OVERFLOW (-1)

// Error handling macro (No-op for verification purpose)
#define BSL_ERR_PUSH_ERROR(code)

// -----------------------------------------------------------------------------
// 2. Encode Functions (Removed static for SAW visibility)
// -----------------------------------------------------------------------------

void EncodeBits1(uint8_t *r, uint16_t *polyF)
{
    for (uint32_t i = 0; i < MLKEM_N / BITS_OF_BYTE; i++)
    {
        r[i] = (uint8_t)polyF[BITS_OF_BYTE * i];
        for (uint32_t j = 1; j < BITS_OF_BYTE; j++)
        {
            r[i] = (uint8_t)(polyF[BITS_OF_BYTE * i + j] << j) | r[i];
        }
    }
}

void EncodeBits4(uint8_t *r, uint16_t *polyF)
{
    for (uint32_t i = 0; i < MLKEM_N / 2; i++)
    { // Two 4 bits are combined into 1 byte.
        r[i] = ((uint8_t)polyF[2 * i] | ((uint8_t)polyF[2 * i + 1] << 4));
    }
}

void EncodeBits5(uint8_t *r, uint16_t *polyF)
{
    uint32_t indexR;
    uint32_t indexF;
    for (uint32_t i = 0; i < MLKEM_N / 8; i++)
    {
        indexR = 5 * i; // Each element in polyF has 5 bits.
        indexF = 8 * i; // Each element in r has 8 bits.
        // 8 polyF elements are padded to 5 bytes.
        r[indexR + 0] = (uint8_t)(polyF[indexF] | (polyF[indexF + 1] << 5));
        r[indexR + 1] =
            (uint8_t)((polyF[indexF + 1] >> 3) | (polyF[indexF + 2] << 2) | (polyF[indexF + 3] << 7));
        r[indexR + 2] = (uint8_t)((polyF[indexF + 3] >> 1) | (polyF[indexF + 4] << 4));
        r[indexR + 3] =
            (uint8_t)((polyF[indexF + 4] >> 4) | (polyF[indexF + 5] << 1) | (polyF[indexF + 6] << 6));
        r[indexR + 4] = (uint8_t)((polyF[indexF + 6] >> 2) | (polyF[indexF + 7] << 3));
    }
}

void EncodeBits10(uint8_t *r, uint16_t *polyF)
{
    uint32_t indexR;
    uint32_t indexF;
    for (uint32_t i = 0; i < MLKEM_N / 4; i++)
    {
        // 4 polyF elements are padded to 5 bytes.
        indexR = 5 * i;
        indexF = 4 * i;
        r[indexR + 0] = (uint8_t)polyF[indexF];
        r[indexR + 1] = (uint8_t)((polyF[indexF] >> 8) | (polyF[indexF + 1] << 2));
        r[indexR + 2] = (uint8_t)((polyF[indexF + 1] >> 6) | (polyF[indexF + 2] << 4));
        r[indexR + 3] = (uint8_t)((polyF[indexF + 2] >> 4) | (polyF[indexF + 3] << 6));
        r[indexR + 4] = (uint8_t)(polyF[indexF + 3] >> 2);
    }
}

void EncodeBits11(uint8_t *r, uint16_t *polyF)
{
    uint32_t indexR;
    uint32_t indexF;
    for (uint32_t i = 0; i < MLKEM_N / 8; i++)
    {
        // 8 polyF elements are padded to 11 bytes.
        indexR = 11 * i;
        indexF = 8 * i;
        r[indexR + 0] = (uint8_t)polyF[indexF];
        r[indexR + 1] = (uint8_t)((polyF[indexF] >> 8) | (polyF[indexF + 1] << 3));
        r[indexR + 2] = (uint8_t)((polyF[indexF + 1] >> 5) | (polyF[indexF + 2] << 6));
        r[indexR + 3] = (uint8_t)((polyF[indexF + 2] >> 2));
        r[indexR + 4] = (uint8_t)((polyF[indexF + 2] >> 10) | (polyF[indexF + 3] << 1));
        r[indexR + 5] = (uint8_t)((polyF[indexF + 3] >> 7) | (polyF[indexF + 4] << 4));
        r[indexR + 6] = (uint8_t)((polyF[indexF + 4] >> 4) | (polyF[indexF + 5] << 7));
        r[indexR + 7] = (uint8_t)((polyF[indexF + 5] >> 1));
        r[indexR + 8] = (uint8_t)((polyF[indexF + 5] >> 9) | (polyF[indexF + 6] << 2));
        r[indexR + 9] = (uint8_t)((polyF[indexF + 6] >> 6) | (polyF[indexF + 7] << 5));
        r[indexR + 10] = (uint8_t)(polyF[indexF + 7] >> 3);
    }
}

void EncodeBits12(uint8_t *r, uint16_t *polyF)
{
    uint32_t i;
    uint16_t t0;
    uint16_t t1;
    for (i = 0; i < MLKEM_N / 2; i++)
    {
        // 2 polyF elements are padded to 3 bytes.
        t0 = polyF[2 * i];
        t1 = polyF[2 * i + 1];
        r[3 * i + 0] = (uint8_t)(t0 >> 0);
        r[3 * i + 1] = (uint8_t)((t0 >> 8) | (t1 << 4));
        r[3 * i + 2] = (uint8_t)(t1 >> 4);
    }
}

// Encodes an array of d-bit integers into a byte array for 1 ≤ d ≤ 12.
void ByteEncode(uint8_t *r, int16_t *polyF, uint8_t bit)
{
    switch (bit)
    {       // Valid bits of each element in polyF.
    case 1: // 1 Used for K-PKE.Decrypt Step 7.
        EncodeBits1(r, (uint16_t *)polyF);
        break;
    case 4: // From FIPS 203 Table 2, dv = 4
        EncodeBits4(r, (uint16_t *)polyF);
        break;
    case 5: // dv = 5
        EncodeBits5(r, (uint16_t *)polyF);
        break;
    case 10: // du = 10
        EncodeBits10(r, (uint16_t *)polyF);
        break;
    case 11: // du = 11
        EncodeBits11(r, (uint16_t *)polyF);
        break;
    case 12: // 12 Used for K-PKE.KeyGen Step 19.
        for (int i = 0; i < MLKEM_N; ++i)
        {
            // Pre-processing step mentioned in the provided snippet
            polyF[i] += (polyF[i] >> 15) & MLKEM_Q;
        }
        EncodeBits12(r, (uint16_t *)polyF);
        break;
    default:
        break;
    }
}

// -----------------------------------------------------------------------------
// 3. Decode Functions (Removed static for SAW visibility)
// -----------------------------------------------------------------------------

void DecodeBits1(int16_t *polyF, const uint8_t *a)
{
    uint32_t i;
    uint32_t j;
    for (i = 0; i < MLKEM_N / BITS_OF_BYTE; i++)
    {
        // 1 byte data is decoded into 8 polyF elements.
        for (j = 0; j < BITS_OF_BYTE; j++)
        {
            polyF[BITS_OF_BYTE * i + j] = (a[i] >> j) & 0x01;
        }
    }
}

void DecodeBits4(int16_t *polyF, const uint8_t *a)
{
    uint32_t i;
    for (i = 0; i < MLKEM_N / 2; i++)
    {
        // 1 byte data is decoded into 2 polyF elements.
        polyF[2 * i] = a[i] & 0xF;
        polyF[2 * i + 1] = (a[i] >> 4) & 0xF;
    }
}

void DecodeBits5(int16_t *polyF, const uint8_t *a)
{
    uint32_t indexF;
    uint32_t indexA;
    for (uint32_t i = 0; i < MLKEM_N / 8; i++)
    {
        // 8 byte data is decoded into 5 polyF elements.
        indexF = 8 * i;
        indexA = 5 * i;
        // value & 0x1F is used to obtain 5 bits.
        polyF[indexF + 0] = ((a[indexA + 0] >> 0)) & 0x1F;
        polyF[indexF + 1] = ((a[indexA + 0] >> 5) | (a[indexA + 1] << 3)) & 0x1F;
        polyF[indexF + 2] = ((a[indexA + 1] >> 2)) & 0x1F;
        polyF[indexF + 3] = ((a[indexA + 1] >> 7) | (a[indexA + 2] << 1)) & 0x1F;
        polyF[indexF + 4] = ((a[indexA + 2] >> 4) | (a[indexA + 3] << 4)) & 0x1F;
        polyF[indexF + 5] = ((a[indexA + 3] >> 1)) & 0x1F;
        polyF[indexF + 6] = ((a[indexA + 3] >> 6) | (a[indexA + 4] << 2)) & 0x1F;
        polyF[indexF + 7] = ((a[indexA + 4] >> 3)) & 0x1F;
    }
}

void DecodeBits10(int16_t *polyF, const uint8_t *a)
{
    uint32_t indexF;
    uint32_t indexA;
    for (uint32_t i = 0; i < MLKEM_N / 4; i++)
    {
        // 5 byte data is decoded into 4 polyF elements.
        indexF = 4 * i;
        indexA = 5 * i;
        // value & 0x3FF is used to obtain 10 bits.
        polyF[indexF + 0] = ((a[indexA + 0] >> 0) | ((uint16_t)a[indexA + 1] << 8)) & 0x3FF;
        polyF[indexF + 1] = ((a[indexA + 1] >> 2) | ((uint16_t)a[indexA + 2] << 6)) & 0x3FF;
        polyF[indexF + 2] = ((a[indexA + 2] >> 4) | ((uint16_t)a[indexA + 3] << 4)) & 0x3FF;
        polyF[indexF + 3] = ((a[indexA + 3] >> 6) | ((uint16_t)a[indexA + 4] << 2)) & 0x3FF;
    }
}

void DecodeBits11(int16_t *polyF, const uint8_t *a)
{
    uint32_t indexF;
    uint32_t indexA;
    for (uint32_t i = 0; i < MLKEM_N / 8; i++)
    {
        // use type conversion because 11 > 8
        indexF = 8 * i;
        indexA = 11 * i;
        // value & 0x7FF is used to obtain 11 bits.
        polyF[indexF + 0] = ((a[indexA + 0] >> 0) | ((uint16_t)a[indexA + 1] << 8)) & 0x7FF;
        polyF[indexF + 1] = ((a[indexA + 1] >> 3) | ((uint16_t)a[indexA + 2] << 5)) & 0x7FF;
        polyF[indexF + 2] = ((a[indexA + 2] >> 6) | ((uint16_t)a[indexA + 3] << 2) |
                             ((uint16_t)a[indexA + 4] << 10)) &
                            0x7FF;
        polyF[indexF + 3] = ((a[indexA + 4] >> 1) | ((uint16_t)a[indexA + 5] << 7)) & 0x7FF;
        polyF[indexF + 4] = ((a[indexA + 5] >> 4) | ((uint16_t)a[indexA + 6] << 4)) & 0x7FF;
        polyF[indexF + 5] = ((a[indexA + 6] >> 7) | ((uint16_t)a[indexA + 7] << 1) |
                             ((uint16_t)a[indexA + 8] << 9)) &
                            0x7FF;
        polyF[indexF + 6] = ((a[indexA + 8] >> 2) | ((uint16_t)a[indexA + 9] << 6)) & 0x7FF;
        polyF[indexF + 7] = ((a[indexA + 9] >> 5) | ((uint16_t)a[indexA + 10] << 3)) & 0x7FF;
    }
}

int32_t DecodeBits12(int16_t *polyF, const uint8_t *a)
{
    uint32_t i;
    for (i = 0; i < MLKEM_N / 2; i++)
    {
        // 3 byte data is decoded into 2 polyF elements, value & 0xFFF is used to obtain 12 bits.
        polyF[2 * i] = ((a[3 * i + 0] >> 0) | ((uint16_t)a[3 * i + 1] << 8)) & 0xFFF;
        polyF[2 * i + 1] = ((a[3 * i + 1] >> 4) | ((uint16_t)a[3 * i + 2] << 4)) & 0xFFF;

        // Overflow check (Section 7.2 of NIST.FIPS.203)
        if (polyF[2 * i] >= MLKEM_Q || polyF[2 * i + 1] >= MLKEM_Q)
        {
            BSL_ERR_PUSH_ERROR(CRYPT_MLKEM_DECODE_KEY_OVERFLOW);
            return CRYPT_MLKEM_DECODE_KEY_OVERFLOW;
        }
    }
    return CRYPT_SUCCESS;
}

// Decodes a byte array into an array of d-bit integers for 1 ≤ d ≤ 12.
int32_t ByteDecode(int16_t *polyF, const uint8_t *a, uint8_t bit)
{
    switch (bit)
    {
    case 1:
        DecodeBits1(polyF, a);
        break;
    case 4:
        DecodeBits4(polyF, a);
        break;
    case 5:
        DecodeBits5(polyF, a);
        break;
    case 10:
        DecodeBits10(polyF, a);
        break;
    case 11:
        DecodeBits11(polyF, a);
        break;
    case 12:
        return DecodeBits12(polyF, a);
    default:
        return -1; // Unknown bit depth
    }
    return CRYPT_SUCCESS;
}