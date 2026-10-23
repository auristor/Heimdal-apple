#ifndef __crypto_header__
#define __crypto_header__

#ifndef PACKAGE_NAME
#error "need config.h"
#endif

#ifdef KRB5
#include <krb5-types.h>
#endif

#ifdef __APPLE_TARGET_EMBEDDED__

/*
 * The CommonDigestSPI.h / CommonCryptorSPI.h / CommonRandomSPI.h interfaces are
 * private to Apple's internal SDKs and are not present in the public
 * iOS/tvOS/watchOS SDKs. CCDGlue.h declares Heimdal's hc_* equivalents, which
 * lib/hcrypto/ccdigest.c implements on top of the public CommonCrypto digest
 * primitives. The non-SPI public headers below cover the rest.
 */
#include <CommonCrypto/CommonDigest.h>
#include <CommonCrypto/CommonCryptor.h>
#include <CommonCrypto/CommonHMAC.h>
#include <CommonCrypto/CommonRandom.h>

#include <hcrypto/CCDGlue.h>

/*
 * CCDGlue.h above already declares the CCDesIsWeakKey()/CCDesSetOddParity()/
 * CCDesCBCCksum() helpers (redirected onto Heimdal's hc_* implementations in
 * ccmisc.c) for the case where CommonCryptorSPI.h is unavailable.
 *
 * CCDigestAlgorithm is the CommonDigestSPI.h enum for naming a digest; on public
 * SDKs the equivalent is CCDGlue.h's CCDigestAlg, a const pointer to the
 * algorithm descriptor. Both are opaque handles passed straight back to
 * CCDigestCreate()/CCDigest().
 */
#ifndef CCDigestAlgorithm
#define CCDigestAlgorithm CCDigestAlg
#endif

#else

#include <CommonCrypto/CommonDigest.h>
#include <CommonCrypto/CommonCryptor.h>
#include <CommonCrypto/CommonHMAC.h>

#include <CommonCrypto/CommonDigestSPI.h>
#include <CommonCrypto/CommonCryptorSPI.h>
#include <CommonCrypto/CommonRandomSPI.h>
#endif
#ifndef __APPLE_TARGET_EMBEDDED__
#include <hcrypto/des.h>
#include <hcrypto/rc4.h>
#include <hcrypto/rc2.h>
#include <hcrypto/rand.h>
#include <hcrypto/pkcs12.h>
#include <hcrypto/engine.h>
#include <hcrypto/hmac.h>
#endif

#include <hcrypto/evp.h>
#include <hcrypto/ui.h>
#include <hcrypto/ec.h>
#include <hcrypto/ecdsa.h>
#include <hcrypto/ecdh.h>

#ifndef CC_DIGEST_MAX_OUTPUT_SIZE
#define CC_DIGEST_MAX_OUTPUT_SIZE 128
#endif


#endif /* __crypto_header__ */
