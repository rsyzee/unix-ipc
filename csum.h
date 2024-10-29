#ifndef SIMD_CSUM
#define SIMD_CSUM

#include <emmintrin.h>
#include <immintrin.h>
#include <stdint.h>

uint32_t crc32_table[256];
#ifdef __SSE__
static void __attribute__((constructor)) init_crc32_table(void) {
    const __m128i polynomial = _mm_set1_epi32(0xEDB88320);
    const __m128i one = _mm_set1_epi32(1);
    
    #pragma unroll(4) 
    for (int i = 0; i < 256; i += 4) {
        __m128i values = _mm_set_epi32(i + 3, i + 2, i + 1, i);
        
        #pragma unroll(8)
        for (int j = 0; j < 8; j++) {
            __m128i lsb = _mm_and_si128(values, one);
            __m128i mask = _mm_cmpeq_epi32(lsb, one);
            values = _mm_srli_epi32(values, 1);
            __m128i masked_poly = _mm_and_si128(polynomial, mask);
            values = _mm_xor_si128(values, masked_poly);
        }
        
        _mm_store_si128((__m128i*)&crc32_table[i], values);
    }
}

static uint32_t calculate_crc32(const void* data, size_t len) {
    const uint8_t* buf = (const uint8_t*)data;
    __m128i crc = _mm_set1_epi32(0xFFFFFFFF);
    
    // Process 4 bytes at a time using SSE2
    for (size_t i = 0; i < len; i += 4) {
        __m128i data_block = _mm_loadu_si128((const __m128i*)(buf + i));
        
        // Extract bytes and do table lookups
        uint32_t idx = _mm_cvtsi128_si32(data_block);
        crc = _mm_xor_si128(
            _mm_srli_epi32(crc, 8),
            _mm_set1_epi32(crc32_table[(crc[0] ^ idx) & 0xFF])
        );
    }
    
    return _mm_cvtsi128_si32(crc) ^ 0xFFFFFFFF;
}



#elif defined(__ARM_NEON)
#include <arm_neon.h>

static void init_crc32_table() {
    uint32x4_t polynomial = vdupq_n_u32(0xEDB88320);
    
    for (int i = 0; i < 256; i += 4) {
        uint32x4_t values = vcreate_u32((uint64_t)i | ((uint64_t)(i + 1) << 32));
        values = vcombine_u32(vget_low_u32(values), 
                             vcreate_u32((uint64_t)(i + 2) | ((uint64_t)(i + 3) << 32)));
        
        for (int j = 0; j < 8; j++) {
            uint32x4_t lsb = vandq_u32(values, vdupq_n_u32(1));
            
            values = vshrq_n_u32(values, 1);
            
            uint32x4_t masked_poly = vandq_u32(polynomial, vceqq_u32(lsb, vdupq_n_u32(1)));
            values = veorq_u32(values, masked_poly);
        }
        
        // Store results back to memory
        vst1q_u32(&crc32_table[i], values);
    }
}

#if defined(__aarch64__)
static uint32_t calculate_crc32(const void* data, size_t len) {
    const uint8_t* buf = (const uint8_t*)data;
    uint32_t crc = 0xFFFFFFFF;
    size_t i = 0;

    for (; i + 16 <= len; i += 16) {
        uint64_t data1 = *(const uint64_t*)(buf + i);
        uint64_t data2 = *(const uint64_t*)(buf + i + 8);
        
        crc = __crc32d(crc, data1);
        crc = __crc32d(crc, data2);
    }
    
    if (i + 8 <= len) {
        uint64_t data = *(const uint64_t*)(buf + i);
        crc = __crc32d(crc, data);
        i += 8;
    }
    
    if (i + 4 <= len) {
        uint32_t data = *(const uint32_t*)(buf + i);
        crc = __crc32w(crc, data);
        i += 4;
    }
    
    while (i < len) {
        crc = __crc32b(crc, buf[i]);
        i++;
    }
    
    return crc ^ 0xFFFFFFFF;
}
#else

static uint32_t calculate_crc32(const void* data, size_t len) {
    const uint8_t* buf = (const uint8_t*)data;
    uint32_t crc = 0xFFFFFFFF;
    size_t i = 0;
    
    while (i + 16 <= len) {
        uint8x16_t data = vld1q_u8(buf + i);
        uint32x4_t crc_val = vdupq_n_u32(crc);
        
        for (int j = 0; j < 4; j++) {
            uint32_t val = vgetq_lane_u8(vreinterpretq_u8_u32(data), j*4);
            crc = crc32_table[(crc ^ val) & 0xFF] ^ (crc >> 8);
            val = vgetq_lane_u8(vreinterpretq_u8_u32(data), j*4 + 1);
            crc = crc32_table[(crc ^ val) & 0xFF] ^ (crc >> 8);
            val = vgetq_lane_u8(vreinterpretq_u8_u32(data), j*4 + 2);
            crc = crc32_table[(crc ^ val) & 0xFF] ^ (crc >> 8);
            val = vgetq_lane_u8(vreinterpretq_u8_u32(data), j*4 + 3);
            crc = crc32_table[(crc ^ val) & 0xFF] ^ (crc >> 8);
        }
        
        i += 16;
    }
    
    while (i < len) {
        crc = crc32_table[(crc ^ buf[i]) & 0xFF] ^ (crc >> 8);
        i++;
    }
    
    return crc ^ 0xFFFFFFFF;
}


#endif

#endif

#endif