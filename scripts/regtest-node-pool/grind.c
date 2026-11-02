/*
 * Nonce grinder for cpu_miner.py (node pool test harness). Built by harness.py into its work
 * directory and loaded with ctypes, which releases the GIL for the call, so the miner threads of
 * one process grind on separate cores. Signet's minimum difficulty is about 4.8M hashes a block,
 * out of a pure-Python miner's reach at harness pace; this does the same search natively.
 *
 *   gcc -O2 -shared -fPIC grind.c -lcrypto -o grind.so
 *
 * grind(header76, target_be, start, count): the first nonce in [start, start + count) whose
 * double-SHA256 of header76 || nonce (little-endian), read as a little-endian number, is at or
 * below target_be (32 bytes, big-endian). Returns -1 if none.
 */
#define OPENSSL_SUPPRESS_DEPRECATED
#include <openssl/sha.h>
#include <stdint.h>
#include <string.h>

static int at_or_below(const unsigned char *hash_le, const unsigned char *target_be)
{
    for (int i = 0; i < 32; i++) {
        unsigned char h = hash_le[31 - i], t = target_be[i];
        if (h != t)
            return h < t;
    }
    return 1;
}

int64_t grind(const unsigned char *header76, const unsigned char *target_be, uint32_t start,
              uint32_t count)
{
    SHA256_CTX mid;
    SHA256_Init(&mid);
    SHA256_Update(&mid, header76, 64);
    unsigned char tail[16], h1[32], h2[32];
    memcpy(tail, header76 + 64, 12);
    for (uint64_t i = 0; i < count; i++) {
        uint32_t nonce = start + (uint32_t)i;
        tail[12] = nonce & 0xff;
        tail[13] = (nonce >> 8) & 0xff;
        tail[14] = (nonce >> 16) & 0xff;
        tail[15] = (nonce >> 24) & 0xff;
        SHA256_CTX c = mid;
        SHA256_Update(&c, tail, 16);
        SHA256_Final(h1, &c);
        SHA256(h1, 32, h2);
        if (at_or_below(h2, target_be))
            return nonce;
    }
    return -1;
}
