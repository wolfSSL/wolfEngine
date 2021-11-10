/* we_random.c
 *
 * Copyright (C) 2019-2021 wolfSSL Inc.
 *
 * This file is part of wolfengine.
 *
 * wolfengine is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfengine is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#include <wolfengine/we_internal.h>

#ifdef WE_HAVE_RANDOM

#ifdef WE_STATIC_WOLFSSL
extern int wc_RNG_DRBG_Reseed(WC_RNG* rng, const byte* seed, word32 seedSz);
#if OPENSSL_VERSION_NUMBER < 0x10100000L
extern int wc_GenerateSeed(OS_Seed* os, byte* seed, int sz);
#endif
#else
/* Hash of all the seed so far. */
unsigned char we_seed[WC_SHA256_DIGEST_SIZE] = {0,};
/* Have added to global seed. */
int haveSeed = 0;
#endif

#ifndef WE_STATIC_WOLFSSL
/**
 * Mix the seed into the buffer.
 *
 * Caller must put lock around this call if necessary.
 *
 * @param  buf      [out]  Buffer holding random.
 * @param  num      [in]   Number of random bytes.
 * @param  seed     [in]   Buffer holding seed data.
 * @param  seedLen  [in]   Number of seed bytes.
 * @returns 1 when successful and 0 on fauilure.
 */
static int we_rand_mix_seed(unsigned char* buf, int num,
                            const unsigned char* seed, int seedLen)
{
    int ret = 1;
    int rc;
    wc_Sha256 sha256;
    unsigned char seedHash[WC_SHA256_DIGEST_SIZE];
    unsigned char hash[WC_SHA256_DIGEST_SIZE] = {0,};
    int i;
    int j;

    WOLFENGINE_ENTER(WE_LOG_RNG, "we_rand_mix_seed");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_RNG, "ARGS [buf = %p, num = %d, seed = %p, "
                           "seedLen = %d]", buf, num, seed, seedLen);

    rc = wc_InitSha256(&sha256);
    if (rc != 0) {
        WOLFENGINE_ERROR_FUNC(WE_LOG_RNG, "wc_InitSha256", rc);
        ret = 0;
    }
    if (rc == 0) {
        /* Set the base seed hash. */
        if (seed != we_seed) {
            /* Calculate hash of seed to save from hashing long data. */
            rc = wc_Sha256Update(&sha256, seed, seedLen);
            if (rc != 0) {
                WOLFENGINE_ERROR_FUNC(WE_LOG_RNG, "wc_Sha256Update", rc);
                ret = 0;
            }
            rc = wc_Sha256Final(&sha256, seedHash);
            if (rc != 0) {
                WOLFENGINE_ERROR_FUNC(WE_LOG_RNG, "wc_Sha256Final", rc);
                ret = 0;
            }
        }
        else {
            /* Use the current hash of the seed data. */
            XMEMCPY(seedHash, seed, seedLen);
        }

        /* XOR unique blocks into random data. */
        for (i = 0; i < num; i += sizeof(hash)) {
            int len = num - i;
            /* Calculate #bytes to be XORed into buffer. */
            if (len > (int)sizeof(hash)) {
                len = (int)sizeof(hash);
            }
            /* Calculate hash of seed hash and last hash. */
            rc = wc_Sha256Update(&sha256, seedHash, sizeof(seedHash));
            if (rc != 0) {
                WOLFENGINE_ERROR_FUNC(WE_LOG_RNG, "wc_Sha256Update", rc);
                ret = 0;
            }
            rc = wc_Sha256Update(&sha256, hash, sizeof(hash));
            if (rc != 0) {
                WOLFENGINE_ERROR_FUNC(WE_LOG_RNG, "wc_Sha256Update", rc);
                ret = 0;
            }
            /* Put hash into buffer to for next round. */
            rc = wc_Sha256Final(&sha256, hash);
            if (rc != 0) {
               WOLFENGINE_ERROR_FUNC(WE_LOG_RNG, "wc_Sha256Final", rc);
               ret = 0;
            }
            /* XOR this block into the random data. */
            for (j = 0; j < len; j++) {
                buf[i + j] ^= hash[j];
            }
        }

        /* Update global seed if just used - don't leave it in memory. */
        if (seed == we_seed) {
            rc = wc_Sha256Update(&sha256, seedHash, sizeof(seedHash));
            if (rc != 0) {
                WOLFENGINE_ERROR_FUNC(WE_LOG_RNG, "wc_Sha256Update", rc);
                ret = 0;
            }
            rc = wc_Sha256Update(&sha256, hash, sizeof(hash));
            if (rc != 0) {
                WOLFENGINE_ERROR_FUNC(WE_LOG_RNG, "wc_Sha256Update", rc);
                ret = 0;
            }
            /* Put hash into global seed. */
            rc = wc_Sha256Final(&sha256, we_seed);
            if (rc != 0) {
               WOLFENGINE_ERROR_FUNC(WE_LOG_RNG, "wc_Sha256Final", rc);
               ret = 0;
            }
        }

        wc_Sha256Free(&sha256);
    }

    WOLFENGINE_LEAVE(WE_LOG_RNG, "we_rand_mix_seed", ret);

    return ret;
}
#endif

/**
 * Seed the global random number generator.
 *
 * @param  buf  [in]  Buffer holding seed data.
 * @param  num  [in]  Number of bytes in buffer.
 */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
static void we_rand_seed(const void *buf, int num)
#else
static int we_rand_seed(const void *buf, int num)
#endif
{
    int ret = 1;
#if defined(WE_STATIC_WOLFSSL) || !defined(WE_SINGLE_THREADED)
    int rc;
#endif

    WOLFENGINE_ENTER(WE_LOG_RNG, "we_rand_seed");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_RNG, "ARGS [buf = %p, num = %d]", buf, num);

#ifndef WE_SINGLE_THREADED
    /* Lock for access to globals. */
    rc = wc_LockMutex(we_rng_mutex);
    if (rc != 0) {
        WOLFENGINE_ERROR_FUNC(WE_LOG_RNG, "wc_LockMutex", rc);
        ret = 0;
    }
    else
#endif
    {
#ifdef WE_STATIC_WOLFSSL
        /* Add the seed to the underlying random number generator. */
        rc = wc_RNG_DRBG_Reseed(we_rng, buf, num);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_RNG, "wc_RNG_DRBG_Reseed", rc);
            ret = 0;
        }
#else
        /* Mix the seed into the global seed. */
        (void)we_rand_mix_seed(we_seed, sizeof(we_seed),
                (const unsigned char*)buf, num);
        haveSeed = 1;
#endif
    #ifndef WE_SINGLE_THREADED
        wc_UnLockMutex(we_rng_mutex);
    #endif
    }

    WOLFENGINE_LEAVE(WE_LOG_RNG, "we_rand_seed", ret);

    (void)ret;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    return ret;
#endif
}

/* Note: from OpensSL 1.1.0 onwards RAND_bytes no longer gets true entropy.
 * There are public and private randoms that are each seeded from entropy.
 * No way to tell when RAND_priv_rand() is called with methods.
 * Use pseudo-bytes implementation when RAND_bytes(), RAND_priv_bytes() and
 * RAND_pseudo_bytes() are called.
 */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
/**
 * Generate true random.
 *
 * @param  buf  [out]  Buffer to hold random.
 * @param  num  [in]   Number of bytes to generate.
 * @returns 1 when data generated and 0 on failure.
 */
static int we_rand_bytes(unsigned char *buf, int num)
{
    int ret = 1;
    int rc;
#ifdef WE_STATIC_WOLFSSL
    OS_Seed os;
#else
    WC_RNG rng;
#endif

    WOLFENGINE_ENTER(WE_LOG_RNG, "we_rand_bytes");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_RNG, "ARGS [buf = %p, num = %d]", buf, num);

#ifdef WE_STATIC_WOLFSSL
    /* Generate true random using internal API. */
    rc = wc_GenerateSeed(&os, buf, num);
    if (rc != 0) {
        WOLFENGINE_ERROR_FUNC(WE_LOG_RNG, "wc_GenerateSeed", rc);
        ret = 0;
    }

#else
    /* Create a new random number generator that is seeded with true random. */
    rc = wc_InitRng(&rng);
    if (rc != 0) {
        WOLFENGINE_ERROR_FUNC(WE_LOG_RNG, "wc_InitRng", rc);
        ret = 0;
    }
    else {
        /* Generate true random. */
        rc = wc_RNG_GenerateBlock(&rng, buf, num);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_RNG, "wc_RNG_GenerateBlock", rc);
            ret = 0;
        }

        /* Dispose of random number generator. */
        rc = wc_FreeRng(&rng);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_RNG, "wc_FreeRng", rc);
            ret = 0;
        }
    }

#endif

    WOLFENGINE_LEAVE(WE_LOG_RNG, "we_rand_bytes", ret);

    return ret;
}
#endif

static void we_rand_cleanup(void)
{
    /* Global random cleanup done in internal.c: we_final_random(). */
    WOLFENGINE_ENTER(WE_LOG_RNG, "we_rand_cleanup");
    WOLFENGINE_LEAVE(WE_LOG_RNG, "we_rand_cleanup", 1);
}

/**
 * Add seed of that has the entropy specified.
 *
 * @param  buf      [in]  Buffer holding seed data.
 * @param  num      [in]  Number of bytes in buffer.
 * @param  entropy  [in]  Amount of entropy in seed data.
 */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
static void we_rand_add(const void *buf, int num, double entropy)
#else
static int we_rand_add(const void *buf, int num, double entropy)
#endif
{
    int ret;

    WOLFENGINE_ENTER(WE_LOG_RNG, "we_rand_add");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_RNG, "ARGS [buf = %p, num = %d, "
                           "entropy = %d]", buf, num, entropy);

    /* Call seed implementation - entropy not used. */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    we_rand_seed(buf, num);
    ret = 1;
#else
    ret = we_rand_seed(buf, num);
#endif
    (void)entropy;

    WOLFENGINE_LEAVE(WE_LOG_RNG, "we_rand_add", ret);
    (void)ret;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    return ret;
#endif
}

/**
 * Generate pseudo-random data.
 *
 * @param  buf  [out]  Buffer to fill with random.
 * @param  num  [in]   Number of bytes to generate.
 * @returns 1 when data generated and 0 on failure.
 */
static int we_rand_pseudorand(unsigned char *buf, int num)
{
    int ret = 1;
    int rc;

    WOLFENGINE_ENTER(WE_LOG_RNG, "we_rand_pseudorand");
    WOLFENGINE_MSG_VERBOSE(WE_LOG_RNG, "ARGS [buf = %p, num = %d]",
                           buf, num);

#ifndef WE_SINGLE_THREADED
    rc = wc_LockMutex(we_rng_mutex);
    if (rc != 0) {
        WOLFENGINE_ERROR_FUNC(WE_LOG_RNG, "wc_LockMutex", rc);
    }
    else
#endif
    {
        /* Use global random to generator pseudo-random data. */
        rc = wc_RNG_GenerateBlock(we_rng, buf, num);
        if (rc != 0) {
            WOLFENGINE_ERROR_FUNC(WE_LOG_RNG, "wc_RNG_GenerateBlock", rc);
            ret = 0;
        }
    #ifndef WE_STATIC_WOLFSSL
        /* Mix global seed if RAND_add() or RAND_seed() has been called. */
        if (haveSeed) {
            ret = we_rand_mix_seed(buf, num, we_seed, sizeof(we_seed));
        }
    #endif
    #ifndef WE_SINGLE_THREADED
        wc_UnLockMutex(we_rng_mutex);
    #endif
    }

    WOLFENGINE_LEAVE(WE_LOG_RNG, "we_rand_pseudorand", ret);

    return ret;
}

/**
 * Random entropy status.
 *
 * @returns 1 to indicate no seeding required.
 */
static int we_rand_status(void)
{
    WOLFENGINE_ENTER(WE_LOG_RNG, "we_rand_status");
    WOLFENGINE_LEAVE(WE_LOG_RNG, "we_rand_status", 1);

    /* Always have enough entropy. */
    return 1;
}

/**
 * Random number generator method.
 */
RAND_METHOD we_rand_method ={
    we_rand_seed,
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    we_rand_bytes,
#else
    /* See note above we_rand_bytes. */
    we_rand_pseudorand,
#endif
    we_rand_cleanup,
    we_rand_add,
    we_rand_pseudorand,
    we_rand_status,
};

/**
 * Random number generator method reference.
 */
RAND_METHOD *we_random_method = &we_rand_method;

#endif /* WE_HAVE_DH */
