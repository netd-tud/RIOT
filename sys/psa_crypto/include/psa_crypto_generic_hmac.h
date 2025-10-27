/*
 * Copyright (C) 2025 TU Dresden
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#pragma once

/**
 * @ingroup     sys_psa_crypto
 * @defgroup    sys_psa_crypto_generic_hmac  PSA Generic HMAC
 * @{
 *
 * @file
 * @brief       Function declarations for generic PSA Crypto HMAC implementation.
 *
 * @author      Armin Wolf <armin.wolf@mailbox.tu-dresden.de>
 *
 */

#ifdef __cplusplus
extern "C" {
#endif

#include "kernel_defines.h"
#include "psa/algorithm.h"
#include "psa/error.h"
#include "psa/mac/types.h"

/**
 * @brief   Low level function to compute a generic HMAC.
 *          See @ref psa_mac_compute()
 */
psa_status_t psa_generic_hmac_compute(const uint8_t *key_data,
                                      size_t key_length,
                                      psa_algorithm_t alg,
                                      const uint8_t *input,
                                      size_t input_length,
                                      uint8_t *mac,
                                      size_t mac_size,
                                      size_t *mac_length,
                                      uint8_t *block);

/**
 * @brief   Low level function to verify a generic HMAC.
 *          See @ref psa_mac_verify()
 */
psa_status_t psa_generic_hmac_verify(const uint8_t *key_data,
                                     size_t key_length,
                                     psa_algorithm_t alg,
                                     const uint8_t *input,
                                     size_t input_length,
                                     const uint8_t *mac,
                                     size_t mac_length,
                                     uint8_t *block);

/**
 * @brief   Low level function to initialize the generic HMAC.
 *          See @ref psa_mac_sign_setup() and @ref psa_mac_verify_setup()
 */
psa_status_t psa_generic_hmac_setup(psa_hash_operation_t *hash,
                                    psa_algorithm_t hash_alg,
                                    const uint8_t *key_buffer,
                                    size_t key_buffer_size,
                                    uint8_t *buffer,
                                    size_t buffer_size);

/**
 * @brief   Low level function to feed data into the generic HMAC.
 *          See @ref psa_mac_update()
 */
psa_status_t psa_generic_hmac_update(psa_hash_operation_t *hash,
                                     const uint8_t *input,
                                     size_t input_length);

/**
 * @brief   Low level function to finish the generic HMAC.
 *          See @ref psa_mac_sign_finish()
 */
psa_status_t psa_generic_hmac_sign_finish(psa_hash_operation_t *hash,
                                          psa_algorithm_t hash_alg,
                                          uint8_t *mac,
                                          size_t mac_size,
                                          size_t *mac_length,
                                          uint8_t *buffer,
                                          size_t buffer_size);

/**
 * @brief   Low level function to verify the generic HMAC.
 *          See @ref psa_mac_verify_finish()
 */
psa_status_t psa_generic_hmac_verify_finish(psa_hash_operation_t *hash,
                                            psa_algorithm_t hash_alg,
                                            const uint8_t *mac,
                                            size_t mac_length,
                                            uint8_t *buffer,
                                            size_t buffer_size);

#ifdef __cplusplus
}
#endif

/**@}*/
