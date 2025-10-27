/*
 * Copyright (C) 2025 TU Dresden
 * Copyright (C) 2021 HAW Hamburg
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#pragma once

#include "psa/algorithm.h"

/**
 * @ingroup     sys_psa_crypto
 * @{
 *
 * @file
 * @brief       MAC type definitions for the PSA Crypto API
 *
 * @author      Armin Wolf <wolf.armin@mailbox.tu-dresden.de>
 * @author      Lena Boeckmann <lena.boeckmann@haw-hamburg.de>
 *
 */

#ifdef __cplusplus
extern "C" {
#endif

#include "kernel_defines.h"
#include "psa/algorithm.h"

#if IS_USED(MODULE_PSA_GENERIC_HMAC_MD5) || \
    IS_USED(MODULE_PSA_GENERIC_MAC_HMAC_SHA_1) || \
    IS_USED(MODULE_PSA_GENERIC_MAC_HMAC_SHA_224) || \
    IS_USED(MODULE_PSA_GENERIC_MAC_HMAC_SHA_256) || \
    IS_USED(MODULE_PSA_GENERIC_MAC_HMAC_SHA_384) || \
    IS_USED(MODULE_PSA_GENERIC_MAC_HMAC_SHA_512) || \
    IS_USED(MODULE_PSA_GENERIC_MAC_HMAC_SHA_512_224) || \
    IS_USED(MODULE_PSA_GENERIC_MAC_HMAC_SHA_512_256) || \
    IS_USED(MODULE_PSA_GENERIC_MAC_HMAC_SHA3_256) || \
    IS_USED(MODULE_PSA_GENERIC_MAC_HMAC_SHA3_384) || \
    IS_USED(MODULE_PSA_GENERIC_MAC_HMAC_SHA3_512)
#include "psa/mac/generic_hmac_ctx.h"
#endif

#if IS_USED(MODULE_PERIPH_MAC_HMAC_MD5) || \
    IS_USED(MODULE_PERIPH_MAC_HMAC_SHA_1) || \
    IS_USED(MODULE_PERIPH_MAC_HMAC_SHA_224) || \
    IS_USED(MODULE_PERIPH_MAC_HMAC_SHA_256) || \
    IS_USED(MODULE_PERIPH_MAC_HMAC_SHA_384) || \
    IS_USED(MODULE_PERIPH_MAC_HMAC_SHA_512) || \
    IS_USED(MODULE_PERIPH_MAC_HMAC_SHA_512_224) || \
    IS_USED(MODULE_PERIPH_MAC_HMAC_SHA_512_256) || \
    IS_USED(MODULE_PERIPH_MAC_HMAC_SHA3_256) || \
    IS_USED(MODULE_PERIPH_MAC_HMAC_SHA3_384) || \
    IS_USED(MODULE_PERIPH_MAC_HMAC_SHA3_512)
#include "psa_periph_mac_hmac_ctx.h"
#endif

/**
 * @brief   Structure containing the mac contexts needed by the application.
 */
typedef union {
#if IS_USED(MODULE_PSA_MAC_HMAC_MD5) || defined(DOXYGEN)
    psa_mac_hmac_md5_ctx_t md5;                 /**< MD5 context */
#endif
#if IS_USED(MODULE_PSA_MAC_HMAC_SHA_1) || defined(DOXYGEN)
    psa_mac_hmac_sha1_ctx_t sha1;               /**< SHA-1 context */
#endif
#if IS_USED(MODULE_PSA_MAC_HMAC_SHA_224) || defined(DOXYGEN)
    psa_mac_hmac_sha224_ctx_t sha224;           /**< SHA-224 context */
#endif
#if IS_USED(MODULE_PSA_MAC_HMAC_SHA_256) || defined(DOXYGEN)
    psa_mac_hmac_sha256_ctx_t sha256;           /**< SHA-256 context */
#endif
#if IS_USED(MODULE_PSA_MAC_HMAC_SHA_384) || defined(DOXYGEN)
    psa_mac_hmac_sha384_ctx_t sha384;           /**< SHA-384 context */
#endif
#if IS_USED(MODULE_PSA_MAC_HMAC_SHA_512) || defined(DOXYGEN)
    psa_mac_hmac_sha512_ctx_t sha512;           /**< SHA-512 context */
#endif
#if IS_USED(MODULE_PSA_MAC_HMAC_SHA3_256) || defined(DOXYGEN)
    psa_mac_hmac_sha3_256_ctx_t sha3_256;       /**< SHA-3-256 context */
#endif
#if IS_USED(MODULE_PSA_MAC_HMAC_SHA3_384) || defined(DOXYGEN)
    psa_mac_hmac_sha3_384_ctx_t sha3_384;       /**< SHA-3-384 context */
#endif
#if IS_USED(MODULE_PSA_MAC_HMAC_SHA3_512) || defined(DOXYGEN)
    psa_mac_hmac_sha3_512_ctx_t sha3_512;       /**< SHA-3-512 context */
#endif
#if IS_USED(MODULE_PSA_MAC_HMAC_SHA_512_224) || defined(DOXYGEN)
    psa_mac_hmac_sha512_224_ctx_t sha512_224;   /**< SHA-512/224 context */
#endif
#if IS_USED(MODULE_PSA_MAC_HMAC_SHA_512_256) || defined(DOXYGEN)
    psa_mac_hmac_sha512_256_ctx_t sha512_256;   /**< SHA-512/256 context */
#endif
} psa_mac_context_t;

/**
 * @brief   Structure containing a MAC operation context
 */
struct psa_mac_operation_s {
    psa_algorithm_t alg;    /**< MAC algorithm used for multi-part MAC operations */
#if IS_USED(MODULE_PSA_MAC) || defined(DOXYGEN)
    psa_mac_context_t ctx;  /**< MAC operation context */
#endif
};

/**
 * @brief   The type of the state object for multi-part MAC operations.
 *
 * @details Before calling any function on a MAC operation object, the application must initialize
 *          it by any of the following means:
 *          - Set the object to all-bits-zero, for example:
 *            @code
 *            @ref psa_mac_operation_t operation;
 *            memset(&operation, 0, sizeof(operation));
 *            @endcode
 *          - Initialize the object to logical zero values by declaring the object as static or
 *            global without an explicit initializer, for example:
 *            @code
 *            static @ref psa_mac_operation_t operation;
 *            @endcode
 *          - Initialize the object to the initializer @ref PSA_MAC_OPERATION_INIT, for example:
 *            @code
 *            @ref psa_mac_operation_t operation = @ref PSA_MAC_OPERATION_INIT;
 *            @endcode
 *          - Assign the result of the function @ref psa_mac_operation_init() to the object,
 *            for example:
 *            @code
 *            @ref psa_mac_operation_t operation;
 *            operation = @ref psa_mac_operation_init();
 *            @endcode
 *          This is an implementation-defined type. Applications that make assumptions about the
 *          content of this object will result in in implementation-specific behavior, and are
 *          non-portable.
 */
typedef struct psa_mac_operation_s psa_mac_operation_t;

/**
 * @brief   This macro returns a suitable initializer for a MAC operation object of type
 *          @ref psa_mac_operation_t.
 */
#define PSA_MAC_OPERATION_INIT { 0 }

/**
 * @brief   Return an initial value for a MAC operation object.
 *
 * @return  psa_mac_operation_t
 */
static inline psa_mac_operation_t psa_mac_operation_init(void)
{
    const psa_mac_operation_t v = PSA_MAC_OPERATION_INIT;

    return v;
}

#ifdef __cplusplus
}
#endif

/** @} */
