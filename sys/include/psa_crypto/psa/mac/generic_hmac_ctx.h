/*
 * Copyright (C) 2025 TU Dresden
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#pragma once

#include "psa/hash/algorithm.h"
#include "psa/hash/sizes.h"
#include "psa/hash/types.h"

/**
 * @ingroup     sys_psa_crypto
 * @defgroup    sys_psa_crypto_hmac  PSA Generic HMAC
 * @{
 *
 * @file
 * @brief       Context declarations for generic PSA Crypto HMAC clue code.
 *
 * @author      Armin Wolf <armin.wolf@mailbox.tu-dresden.de>
 *
 */

#ifdef __cplusplus
extern "C" {
#endif

#if IS_USED(MODULE_PSA_GENERIC_HMAC_MD5)
/**
 * @brief   MD5 calculation context for the generic HMAC
 */
typedef struct {
    psa_hash_operation_t hash;                          /**< Hash context*/
    uint8_t block[PSA_HASH_BLOCK_LENGTH(PSA_ALG_MD5)];  /**< Block buffer*/
} psa_mac_hmac_md5_ctx_t;
#endif

#if IS_USED(MODULE_PSA_GENERIC_MAC_HMAC_SHA_1)
/**
 * @brief   SHA-1 calculation context for the generic HMAC
 */
typedef struct {
    psa_hash_operation_t hash;                              /**< Hash context*/
    uint8_t block[PSA_HASH_BLOCK_LENGTH(PSA_ALG_SHA_1)];    /**< Block buffer*/
} psa_mac_hmac_sha1_ctx_t;
#endif

#if IS_USED(MODULE_PSA_GENERIC_MAC_HMAC_SHA_224)
/**
 * @brief   SHA-224 calculation context for the generic HMAC
 */
typedef struct {
    psa_hash_operation_t hash;                              /**< Hash context*/
    uint8_t block[PSA_HASH_BLOCK_LENGTH(PSA_ALG_SHA_224)];  /**< Block buffer*/
} psa_mac_hmac_sha224_ctx_t;
#endif

#if IS_USED(MODULE_PSA_GENERIC_MAC_HMAC_SHA_256)
/**
 * @brief   SHA-256 calculation context for the generic HMAC
 */
typedef struct {
    psa_hash_operation_t hash;                              /**< Hash context*/
    uint8_t block[PSA_HASH_BLOCK_LENGTH(PSA_ALG_SHA_256)];  /**< Block buffer*/
} psa_mac_hmac_sha256_ctx_t;
#endif

#if IS_USED(MODULE_PSA_GENERIC_MAC_HMAC_SHA_384)
/**
 * @brief   SHA-384 calculation context for the generic HMAC
 */
typedef struct {
    psa_hash_operation_t hash;                              /**< Hash context*/
    uint8_t block[PSA_HASH_BLOCK_LENGTH(PSA_ALG_SHA_384)];  /**< Block buffer*/
} psa_mac_hmac_sha384_ctx_t;
#endif

#if IS_USED(MODULE_PSA_GENERIC_MAC_HMAC_SHA_512)
/**
 * @brief   SHA-512 calculation context for the generic HMAC
 */
typedef struct {
    psa_hash_operation_t hash;                              /**< Hash context*/
    uint8_t block[PSA_HASH_BLOCK_LENGTH(PSA_ALG_SHA_512)];  /**< Block buffer*/
} psa_mac_hmac_sha512_ctx_t;
#endif

#if IS_USED(MODULE_PSA_GENERIC_MAC_HMAC_SHA3_256)
/**
 * @brief   SHA-3-256 calculation context for the generic HMAC
 */
typedef struct {
    psa_hash_operation_t hash;                              /**< Hash context*/
    uint8_t block[PSA_HASH_BLOCK_LENGTH(PSA_ALG_SHA3_256)]; /**< Block buffer*/
} psa_mac_hmac_sha3_256_ctx_t;
#endif

#if IS_USED(MODULE_PSA_GENERIC_MAC_HMAC_SHA3_384)
/**
 * @brief   SHA-3-384 calculation context for the generic HMAC
 */
typedef struct {
    psa_hash_operation_t hash;                              /**< Hash context*/
    uint8_t block[PSA_HASH_BLOCK_LENGTH(PSA_ALG_SHA3_384)]; /**< Block buffer*/
} psa_mac_hmac_sha3_384_ctx_t;
#endif

#if IS_USED(MODULE_PSA_GENERIC_MAC_HMAC_SHA3_512)
/**
 * @brief   SHA-3-512 calculation context for the generic HMAC
 */
typedef struct {
    psa_hash_operation_t hash;                              /**< Hash context*/
    uint8_t block[PSA_HASH_BLOCK_LENGTH(PSA_ALG_SHA3_512)]; /**< Block buffer*/
} psa_mac_hmac_sha3_512_ctx_t;
#endif

#if IS_USED(MODULE_PSA_GENERIC_MAC_HMAC_SHA_512_224)
/**
 * @brief   SHA-512-224 calculation context for the generic HMAC
 */
typedef struct {
    psa_hash_operation_t hash;                                  /**< Hash context*/
    uint8_t block[PSA_HASH_BLOCK_LENGTH(PSA_ALG_SHA_512_224)];  /**< Block buffer*/
} psa_mac_hmac_sha512_224_ctx_t;
#endif

#if IS_USED(MODULE_PSA_GENERIC_MAC_HMAC_SHA_512_256)
/**
 * @brief   SHA-512-256 calculation context for the generic HMAC
 */
typedef struct {
    psa_hash_operation_t hash;                                  /**< Hash context*/
    uint8_t block[PSA_HASH_BLOCK_LENGTH(PSA_ALG_SHA_512_256)];  /**< Block buffer*/
} psa_mac_hmac_sha512_256_ctx_t;
#endif

#ifdef __cplusplus
}
#endif

/**@}*/
