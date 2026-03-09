/*
 * Standalone verification target for Parse()
 * Optimized for SAW verification (No stdio dependencies)
 */
#include <stdint.h>
#define MLKEM_Q 3329
#define CRYPT_SUCCESS 0
#define CRYPT_MLKEM_KEYLEN_ERROR (-1)
#define BSL_ERR_PUSH_ERROR(code) 

/*
 * Parse: extract 12-bit values from byte stream into polyNtt[].
 * Returns CRYPT_SUCCESS or CRYPT_MLKEM_KEYLEN_ERROR on insufficient input.
 */
int32_t Parse(uint16_t *polyNtt, const uint8_t *arrayB, uint32_t arrayLen, uint32_t n)
{
    uint32_t i = 0;
    uint32_t j = 0;
    while (j < n) {
        if (i + 3 > arrayLen) {  
            // 返回错误信息
            BSL_ERR_PUSH_ERROR(CRYPT_MLKEM_KEYLEN_ERROR);
            return CRYPT_MLKEM_KEYLEN_ERROR;
        }
        
        // The 4 bits of each byte are combined with the 8 bits of another byte into 12 bits.
        // d1取b0（arrayB[i]）的8位+b1（arrayB[i + 1]）的低4位（拼成12位）
        uint16_t d1 = ((uint16_t)arrayB[i]) + (((uint16_t)arrayB[i + 1] & 0x0f) << 8);
        // d2取b1的高4位+b2的8位（拼成12位）
        uint16_t d2 = (((uint16_t)arrayB[i + 1]) >> 4) + (((uint16_t)arrayB[i + 2]) << 4);
        
        if (d1 < MLKEM_Q) {
            polyNtt[j] = d1;
            j++;
        }
        if (d2 < MLKEM_Q && j < n) {
            polyNtt[j] = d2;
            j++;
        }
        i += 3;
    }
    return CRYPT_SUCCESS;
}
// clang -g -c -emit-llvm -O0 Parse.c -o parse.bc