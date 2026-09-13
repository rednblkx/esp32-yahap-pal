#pragma once

// Compatibility shim bridging mbedtls v3 (public legacy API, IDF <= 5.x)
// and mbedtls v4 / TF-PSA-Crypto (IDF 6.x), where the per-algorithm
// headers moved under mbedtls/private/ and require explicit opt-in.
//
// Only include selection lives here. The crypto logic itself goes through
// the PSA API (psa_hash_*)

#include <mbedtls/build_info.h>

#if MBEDTLS_VERSION_MAJOR >= 4
#ifndef MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS
#define MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS
#endif
#include <mbedtls/private/sha256.h>
#include <mbedtls/private/sha512.h>
#include <mbedtls/private/gcm.h>
#else
#include <mbedtls/sha256.h>
#include <mbedtls/sha512.h>
#include <mbedtls/gcm.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/md.h>
#endif

// bignum: on ESP-IDF the port ships a public wrapper (mbedtls/bignum.h)
// that defines MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS itself and includes
// the private header; on other platforms v4 exposes it only via private/.
#if defined(ESP_PLATFORM) || MBEDTLS_VERSION_MAJOR < 4
#include <mbedtls/bignum.h>
#else
#include <mbedtls/private/bignum.h>
#endif
