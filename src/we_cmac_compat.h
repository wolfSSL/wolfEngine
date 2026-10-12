/* CMAC cleanup compatibility, private to the engine. */
#ifndef WOLFENGINE_CMAC_COMPAT_H
#define WOLFENGINE_CMAC_COMPAT_H

/** Release CMAC state using the module's supported cleanup interface. */
static void we_cmac_free(Cmac *cmac)
{
#if defined(WE_NO_CMAC_FREE) || (defined(HAVE_FIPS) && \
    (!defined(HAVE_FIPS_VERSION) || (HAVE_FIPS_VERSION <= 2)))
#ifdef WE_CMAC_HAS_BUFFERED_STATE
    if (cmac->msg != NULL) {
        OPENSSL_cleanse(cmac->msg, cmac->len);
        /* Legacy wc_CMAC_Grow allocates with the default heap. */
        XFREE(cmac->msg, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
#endif
    wc_AesFree(&cmac->aes);
    OPENSSL_cleanse(cmac, sizeof(*cmac));
#else
    (void)wc_CmacFree(cmac);
#endif
}

#endif /* WOLFENGINE_CMAC_COMPAT_H */
