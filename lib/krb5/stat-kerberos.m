#include "krb5_locl.h"

#include <TargetConditionals.h>
#include <Foundation/Foundation.h>

#if TARGET_OS_OSX

/*
 * CoreAnalytics is an Apple-internal framework and is not present in the public
 * iOS/tvOS/watchOS SDKs. These are fire-and-forget telemetry hooks, so they are
 * simply omitted where the framework is unavailable.
 */
#import <CoreAnalytics/CoreAnalytics.h>

void
_krb5_stat_ASREQ(krb5_context context, krb5_enctype userEnctype,
		 krb5_enctype asEnctype, const char *type, int fast)
{
    @autoreleasepool {
	AnalyticsSendEventLazy(@"com.apple.GSS.Kerberos", ^NSDictionary<NSString *,NSObject *> * _Nullable {
	    return @{
		@"AS_REQ_replykey_et" : @(asEnctype),
		@"AS_REQ_useret_et" : @(userEnctype),
		@"AS_REQ_preauth" : [NSString stringWithCString:type encoding:NSUTF8StringEncoding] ?: @"unknown",
		@"AS_REQ_FAST" : @(fast),
	    };
	});
    }
}

#else

void
_krb5_stat_ASREQ(krb5_context context, krb5_enctype userEnctype,
		 krb5_enctype asEnctype, const char *type, int fast)
{
}

#endif
