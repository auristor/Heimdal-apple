/*
 * ccdigest.c -- CommonCrypto digest glue for platforms without the SPI API.
 *
 * The public CommonCrypto one-shot/streaming digest entry points (CC_MD5*,
 * CC_SHA1*, ...) are available on every platform, but the CommonDigestSPI.h
 * streaming interface (CCDigestCreate/Update/Final, kCCDigest*) is private to
 * Apple's internal SDKs and is absent from the public iOS/tvOS/watchOS SDKs.
 *
 * lib/hcrypto/CCDGlue.h already declares the hc_* flavour of that interface and
 * redirects the public names onto it. This file provides the definitions, each
 * algorithm binding to the corresponding public CommonCrypto primitive.
 */

#include <stdlib.h>
#include <string.h>

#include <krb5-types.h>

#include <CommonCrypto/CommonDigest.h>
#include <CommonCrypto/CommonCryptor.h>
#include "CCDGlue.h"

/*
 * MD4 is deprecated in favour of nothing at all, but Kerberos still needs it for
 * the legacy RC4/DES checksums, so silence the deprecation locally.
 */
#if defined(__APPLE__)
#define CC_HC_SUPPRESS_MD4_DEPRECATION                                             \
    _Pragma("clang diagnostic push")                                              \
        _Pragma("clang diagnostic ignored \"-Wdeprecated-declarations\"")
#define CC_HC_RESTORE_WARNINGS _Pragma("clang diagnostic pop")
#else
#define CC_HC_SUPPRESS_MD4_DEPRECATION
#define CC_HC_RESTORE_WARNINGS
#endif

/*
 * Algorithm identifiers. The value is stored in struct CCDigest_s so that the
 * Update/Final path can dispatch without dereferencing an incomplete type.
 */
enum hc_ccdigest_id {
    HC_CCDIGEST_MD4 = 0,
    HC_CCDIGEST_MD5,
    HC_CCDIGEST_SHA1,
    HC_CCDIGEST_SHA256,
    HC_CCDIGEST_SHA384,
    HC_CCDIGEST_SHA512
};

struct CCDigest_s {
    enum hc_ccdigest_id id;
    size_t block_size;
    size_t output_size;
};

/*
 * Per-stream state. The algorithm is public (all fields of CCDigest_s are
 * known here) but the context type itself stays opaque to callers, matching the
 * CommonDigestSPI contract.
 */
struct CCDigestCtx_s {
    const struct CCDigest_s *alg;
    union {
	CC_MD4_CTX md4;
	CC_MD5_CTX md5;
	CC_SHA1_CTX sha1;
	CC_SHA256_CTX sha256;
	CC_SHA512_CTX sha512;
    } u;
};

#define HC_BLOCK_SIZE 64

const struct CCDigest_s hc_kCCDigestMD4_s = { HC_CCDIGEST_MD4, HC_BLOCK_SIZE, 16 };
const struct CCDigest_s hc_kCCDigestMD5_s = { HC_CCDIGEST_MD5, HC_BLOCK_SIZE, 16 };
const struct CCDigest_s hc_kCCDigestSHA1_s = { HC_CCDIGEST_SHA1, HC_BLOCK_SIZE, 20 };
const struct CCDigest_s hc_kCCDigestSHA256_s = { HC_CCDIGEST_SHA256, HC_BLOCK_SIZE, 32 };
const struct CCDigest_s hc_kCCDigestSHA384_s = { HC_CCDIGEST_SHA384, HC_BLOCK_SIZE, 48 };
const struct CCDigest_s hc_kCCDigestSHA512_s = { HC_CCDIGEST_SHA512, HC_BLOCK_SIZE, 64 };

static int
hc_digest_init(struct CCDigestCtx_s *ctx, const struct CCDigest_s *alg)
{
    int ret;

    ctx->alg = alg;

    switch (alg->id) {
    case HC_CCDIGEST_MD4:
	CC_HC_SUPPRESS_MD4_DEPRECATION
	ret = CC_MD4_Init(&ctx->u.md4);
	break;
    case HC_CCDIGEST_MD5:
	ret = CC_MD5_Init(&ctx->u.md5);
	break;
    case HC_CCDIGEST_SHA1:
	ret = CC_SHA1_Init(&ctx->u.sha1);
	break;
    case HC_CCDIGEST_SHA256:
	ret = CC_SHA256_Init(&ctx->u.sha256);
	break;
    case HC_CCDIGEST_SHA384:
	ret = CC_SHA384_Init(&ctx->u.sha512);
	break;
    case HC_CCDIGEST_SHA512:
	ret = CC_SHA512_Init(&ctx->u.sha512);
	break;
    default:
	return -1;
    }

    /*
     * The CommonCrypto Init routines return 1 on success and 0 on failure.
     * This function returns 0 on success, which is what its caller checks
     * for. Without the inversion every digest fails, and the callers in
     * lib/krb5 (SHA1_checksum() and friends) abort the process.
     */
    return ret == 0 ? -1 : 0;
}

CCDigestRef
CCDigestCreate(CCDigestAlg alg)
{
    struct CCDigestCtx_s *ctx;

    if (alg == NULL)
	return NULL;

    ctx = calloc(1, sizeof(*ctx));
    if (ctx == NULL)
	return NULL;

    if (hc_digest_init(ctx, alg) != 0) {
	free(ctx);
	return NULL;
    }
    return ctx;
}

int
CCDigestUpdate(CCDigestRef ref, const void *data, size_t len)
{
    int ret;

    if (ref == NULL)
	return -1;
    /* A zero-length update is a no-op for every one of these algorithms. */
    if (len == 0)
	return 0;

    switch (ref->alg->id) {
    case HC_CCDIGEST_MD4:
	CC_HC_SUPPRESS_MD4_DEPRECATION
	ret = CC_MD4_Update(&ref->u.md4, data, (CC_LONG)len);
	break;
    case HC_CCDIGEST_MD5:
	ret = CC_MD5_Update(&ref->u.md5, data, (CC_LONG)len);
	break;
    case HC_CCDIGEST_SHA1:
	ret = CC_SHA1_Update(&ref->u.sha1, data, (CC_LONG)len);
	break;
    case HC_CCDIGEST_SHA256:
	ret = CC_SHA256_Update(&ref->u.sha256, data, (CC_LONG)len);
	break;
    case HC_CCDIGEST_SHA384:
	ret = CC_SHA384_Update(&ref->u.sha512, data, (CC_LONG)len);
	break;
    case HC_CCDIGEST_SHA512:
	ret = CC_SHA512_Update(&ref->u.sha512, data, (CC_LONG)len);
	break;
    default:
	return -1;
    }

    /* The CommonCrypto Update routines return 1 on success; this interface
     * returns 0 on success. */
    return ret == 0 ? -1 : 0;
}

int
CCDigestFinal(CCDigestRef ref, void *out)
{
    int ret;

    if (ref == NULL || out == NULL)
	return -1;

    switch (ref->alg->id) {
    case HC_CCDIGEST_MD4:
	CC_HC_SUPPRESS_MD4_DEPRECATION
	ret = CC_MD4_Final(out, &ref->u.md4);
	break;
    case HC_CCDIGEST_MD5:
	ret = CC_MD5_Final(out, &ref->u.md5);
	break;
    case HC_CCDIGEST_SHA1:
	ret = CC_SHA1_Final(out, &ref->u.sha1);
	break;
    case HC_CCDIGEST_SHA256:
	ret = CC_SHA256_Final(out, &ref->u.sha256);
	break;
    case HC_CCDIGEST_SHA384:
	ret = CC_SHA384_Final(out, &ref->u.sha512);
	break;
    case HC_CCDIGEST_SHA512:
	ret = CC_SHA512_Final(out, &ref->u.sha512);
	break;
    default:
	return -1;
    }

    /* The CommonCrypto Final routines return 1 on success; this interface
     * returns 0 on success. */
    return ret == 0 ? -1 : 0;
}

void
CCDigestReset(CCDigestRef ref)
{
    if (ref != NULL)
	(void)hc_digest_init(ref, ref->alg);
}

void
CCDigestDestroy(CCDigestRef ref)
{
    free(ref);
}

int
CCDigest(CCDigestAlg alg, const void *data, size_t len, void *out)
{
    CCDigestRef ref;
    int ret;

    ref = CCDigestCreate(alg);
    if (ref == NULL)
	return -1;

    ret = CCDigestUpdate(ref, data, len);
    if (ret == 0)
	ret = CCDigestFinal(ref, out);

    CCDigestDestroy(ref);
    return ret;
}

size_t
CCDigestBlockSize(CCDigestRef ref)
{
    if (ref == NULL)
	return 0;
    return ref->alg->block_size;
}

size_t
CCDigestOutputSize(CCDigestRef ref)
{
    if (ref == NULL)
	return 0;
    return ref->alg->output_size;
}
