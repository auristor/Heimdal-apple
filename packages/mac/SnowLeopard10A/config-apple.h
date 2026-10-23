
#define HDB_DB_DIR "/var/db/krb5kdc"

#define __APPLE_PRIVATE__ 1
#define __GSS_ITER_CRED_USES_CONST_OID 1

#define __APPLE_USE_RFC_3542 1

#define HEIMDAL_SMALLER 1
#define NO_NTLM 1
#define NO_AFS 1
#define KRB5_DNS_DOMAIN_REALM_DEFAULT 0
#define NO_RAND_FORTUNA_METHOD 1
#define NO_RAND_UNIX_METHOD 1
#define NO_RAND_EGD_METHOD 1

#define HAVE_COMMONCRYPTO_COMMONKEYDERIVATION_H 1
#define HAVE_COMMONCRYPTO_COMMONCRYPTOR_H 1

#define KRB5_FALLBACK_DEFAULT FALSE

/* key derivation */
/* keychain */
/* IP_RECVPKTINFO */
#define HAVE_NOTIFY_H 1
#define KRB5_CONFIGURATION_CHANGE_NOTIFY_NAME "com.apple.Kerberos.configuration-changed"

#define DEFAULT_KDC_LOG_DEST "OSLOG:normal:kdc"

#ifndef PKINIT
#error "no pkinit ?"
#endif

/*
 * These say "the platform provides CCDesIsWeakKey()/CCDesSetOddParity() and the
 * CommonDigestSPI.h CCDigestCreate() family". Both actually live in Apple's
 * *internal* SDKs, so on the public iOS/tvOS/watchOS SDKs leave them undefined and
 * let lib/hcrypto's own implementations (ccmisc.c, ccdigest.c) supply them.
 */
#ifndef __APPLE_TARGET_EMBEDDED__
#define HAVE_CCDESISWEAKKEY 1
#define HAVE_CCDIGESTCREATE 1
#endif

#define HEIM_KRB5_DES3 1
#define HEIM_KRB5_ARCFOUR 0

#ifdef __APPLE_TARGET_EMBEDDED__

/*
 * The "XCACHE" credential-cache type is backed by the HeimCred service, which
 * this tree reaches over a privileged mach XPC connection
 * (xpc_connection_create_mach_service). That API is macOS-only, so on
 * iOS/tvOS/watchOS the XCACHE type is unavailable and the ordinary FILE
 * cache is used instead. lib/krb5/xcache.c is entirely inside #ifdef HAVE_XCC.
 */
#undef XCACHE_IS_API_CACHE
#define KRB5_DEFAULT_CCTYPE (&krb5_fcc_ops)

/* Use the bundled libtommath (LTM) crypto backend on embedded platforms.
   The Security.framework backend (HEIM_HC_SF) relies on SecRSAKey.h /
   SecDH.h, which are absent from the public iOS/tvOS/watchOS SDKs. */
#define HEIM_HC_LTM 1
#define USE_HCRYPTO_LTM 1

#define ENABLE_NTLM 1

#else

#define XCACHE_IS_API_CACHE 1
#define KRB5_DEFAULT_CCTYPE (&krb5_xcc_api_ops)

#define HAVE_XCC 1
#define HAVE_OPENDIRECTORY 1
#define HAVE_CDSA 1
#define HAVE_COMMONCRYPTO_COMMONCRYPTORSPI_H 1

#define ENABLE_NTLM 1
#define ENABLE_SCRAM 1

#ifndef HAVE_KCM
#ifndef __APPLE_TARGET_EMBEDDED__
/* The KCM-compat cache type is implemented in lib/krb5/xcache.c, which is
   only built when HAVE_XCC is set. */
#define ENABLE_KCM_COMPAT 1
#endif
#endif

#define HEIM_KS_P11 1

#endif
