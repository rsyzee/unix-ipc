#ifndef SIMD_CSUM
#define SIMD_CSUM
#include <stdint.h>
#include <stddef.h>

static uint32_t crc32_table[256];
#ifdef __SSE4_2__
#include <nmmintrin.h>

static uint32_t calculate_crc32(const void *data, size_t len) {
    const uint8_t *buf = (const uint8_t*)data;
    uint64_t crc = 0xFFFFFFFF;

    while (len && ((uintptr_t)buf & 7)) {
        crc = _mm_crc32_u8((uint32_t)crc, *buf++);
        len--;
    }

    const uint64_t *buf64 = (const uint64_t*)buf;
    while (len >= 8) {
        crc = _mm_crc32_u64(crc, *buf64++);
        len -= 8;
    }

    buf = (const uint8_t*)buf64;

    while (len--) {
        crc = _mm_crc32_u8((uint32_t)crc, *buf++);
    }

    return (uint32_t)crc ^ 0xFFFFFFFF;
}



#elif defined(__aarch64__)

#include <string.h>
static uint32_t calculate_crc32(const void* data, size_t len) {
	const uint8_t *buf = data;
    uint32_t crc = 0xFFFFFFFF;

    while (len >= 8) {
        uint64_t v;
        memcpy(&v, buf, 8);
        crc = __crc32d(crc, v);
        buf += 8;
        len -= 8;
    }

    while (len >= 4) {
        uint32_t v;
        memcpy(&v, buf, 4);
        crc = __crc32w(crc, v);
        buf += 4;
        len -= 4;
    }

    while (len--) {
        crc = __crc32b(crc, *buf++);
    }

    return crc ^ 0xFFFFFFFF;
}

#else
static void __attribute__((constructor))
init_crc32_table(void) {
	const uint32_t polynomial = 0xEDB88320;

	for (int i = 0; i < 256; i++) {
		uint32_t crc = i;
		for (int j = 0; j < 8; j++) {
			crc = (crc >> 1) ^ ((crc & 1) ? polynomial : 0);
		}
		crc32_table[i] = crc;
	}
}

static uint32_t calculate_crc32(const void *data, size_t len) {
	const uint8_t *buf = (const uint8_t*)data;
	uint32_t crc = 0xFFFFFFFF;

	while (len--) {
		crc = (crc >> 8) ^ crc32_table[(crc & 0xFF) ^ *buf++];
	}

	return crc ^ 0xFFFFFFFF;
}

#endif

#endif // SIMD_CSUM
