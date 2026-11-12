/* Exercise cleanup ownership independently of the installed backend layout. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Each build models one backend layout, independent of engine flags. */
#undef HAVE_FIPS
#undef HAVE_FIPS_VERSION
#undef WE_NO_CMAC_FREE
#undef WE_CMAC_HAS_BUFFERED_STATE
#if defined(WE_TEST_CMAC_INLINE) || defined(WE_TEST_CMAC_BUFFERED)
#define WE_NO_CMAC_FREE
#endif
#ifdef WE_TEST_CMAC_BUFFERED
#define WE_CMAC_HAS_BUFFERED_STATE
#endif

typedef struct Cmac {
    unsigned int aes;
#if !defined(WE_TEST_CMAC_INLINE)
    unsigned char *msg;
    size_t len;
#endif
} Cmac;

static int aesFreed;
static int bufferFreed;
static int bufferCleared = 1;

static void test_cleanse(void *ptr, size_t len)
{
    volatile unsigned char *p = (volatile unsigned char *)ptr;

    while (len-- != 0)
        *p++ = 0;
}

#define OPENSSL_cleanse test_cleanse

static void wc_AesFree(unsigned int *aes)
{
    if (*aes == 1)
        aesFreed++;
    *aes = 0;
}

#if !defined(WE_TEST_CMAC_INLINE)
static void test_free(void *ptr, void *heap, int type)
{
    const unsigned char *p = (const unsigned char *)ptr;
    size_t i;

    if ((heap != NULL) || (type != 1))
        bufferCleared = 0;
    for (i = 0; i < 16; i++) {
        if (p[i] != 0)
            bufferCleared = 0;
    }
    bufferFreed++;
    free(ptr);
}

#define DYNAMIC_TYPE_TMP_BUFFER 1
#define XFREE(ptr, heap, type) test_free((ptr), (heap), (type))
#endif

#if !defined(WE_NO_CMAC_FREE)
static int wc_CmacFree(Cmac *cmac)
{
    OPENSSL_cleanse(cmac->msg, cmac->len);
    XFREE(cmac->msg, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    wc_AesFree(&cmac->aes);
    OPENSSL_cleanse(cmac, sizeof(*cmac));
    return 0;
}
#endif

#include "../src/we_cmac_compat.h"

int main(void)
{
    Cmac cmac;
    const unsigned char *p = (const unsigned char *)&cmac;
    size_t i;
    int err = 0;
#if !defined(WE_TEST_CMAC_INLINE)
    unsigned char *buffer;

    (void)&test_free;
    buffer = (unsigned char *)malloc(16);
    if (buffer == NULL)
        return 1;
    memset(buffer, 0xa5, 16);
#endif

    memset(&cmac, 0, sizeof(cmac));
    cmac.aes = 1;
#if !defined(WE_TEST_CMAC_INLINE)
    cmac.msg = buffer;
    cmac.len = 16;
#endif
    we_cmac_free(&cmac);
    err = aesFreed != 1;
    for (i = 0; i < sizeof(cmac); i++) {
        if (p[i] != 0)
            err = 1;
    }
#if !defined(WE_TEST_CMAC_INLINE)
    if ((bufferFreed != 1) || !bufferCleared)
        err = 1;
    if (bufferFreed == 0)
        free(buffer);
#else
    if ((bufferFreed != 0) || !bufferCleared)
        err = 1;
#endif
    printf("CMAC cleanup ownership: %s\n", err ? "FAIL" : "PASS");
    return err;
}
