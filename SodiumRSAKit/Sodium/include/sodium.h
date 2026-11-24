// clang-format Language: ObjC

#ifndef __SODIUM_H__
#define __SODIUM_H__

#include "export.h"

#ifdef __cplusplus
extern "C" {
#endif

SODIUM_EXPORT
int sodium_init(void)
    __attribute__((warn_unused_result));

/* ---- */

SODIUM_EXPORT
int sodium_set_misuse_handler(void (*handler)(void));

SODIUM_EXPORT
void sodium_misuse(void)
    __attribute__((noreturn));

#ifdef __cplusplus
}
#endif

#include "core.h"
#include "crypto_aead_chacha20poly1305.h"
#include "crypto_auth.h"
#include "crypto_auth_hmacsha256.h"
#include "crypto_auth_hmacsha512.h"
#include "crypto_auth_hmacsha512256.h"
#include "crypto_box.h"
#include "crypto_box_curve25519xsalsa20poly1305.h"
#include "crypto_core_hsalsa20.h"
#include "crypto_core_salsa20.h"
#include "crypto_core_salsa2012.h"
#include "crypto_core_salsa208.h"
#include "crypto_generichash.h"
#include "crypto_generichash_blake2b.h"
#include "crypto_hash.h"
#include "crypto_hash_sha256.h"
#include "crypto_hash_sha512.h"
#include "crypto_onetimeauth.h"
#include "crypto_onetimeauth_poly1305.h"
#include "crypto_pwhash_scryptsalsa208sha256.h"
#include "crypto_scalarmult.h"
#include "crypto_scalarmult_curve25519.h"
#include "crypto_secretbox.h"
#include "crypto_secretbox_xsalsa20poly1305.h"
#include "crypto_shorthash.h"
#include "crypto_shorthash_siphash24.h"
#include "crypto_sign.h"
#include "crypto_sign_ed25519.h"
#include "crypto_stream.h"
//#include "crypto_stream_aes128ctr.h"
//#include "crypto_stream_aes256estream.h"
#include "crypto_stream_chacha20.h"
#include "crypto_stream_salsa20.h"
#include "crypto_stream_salsa2012.h"
#include "crypto_stream_salsa208.h"
#include "crypto_stream_xsalsa20.h"
#include "crypto_verify_16.h"
#include "crypto_verify_32.h"
#include "crypto_verify_64.h"
#include "randombytes.h"
//#include "randombytes_salsa20_random.h"
#include "randombytes_sysrandom.h"
#include "runtime.h"
#include "utils.h"
#include "version.h"

#endif
