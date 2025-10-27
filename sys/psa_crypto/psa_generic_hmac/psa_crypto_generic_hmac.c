/*
 * Copyright (C) 2025 TU Dresden
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     sys_psa_crypto sys_psa_crypto_generic_hmac
 * @{
 *
 * @file
 * @brief       Generic PSA Crypto HMAC implementation, based on RFC 2104.
 *
 * @author      Armin Wolf <armin.wolf@mailbox.tu-dresden.de>
 *
 */

#ifdef __cplusplus
extern "C" {
#endif

#include "kernel_defines.h"
#include "psa/algorithm.h"
#include "psa/crypto.h"
#include "psa/error.h"
#include "psa/mac/types.h"
#include "psa_crypto_generic_hmac.h"
#include "string_utils.h"

static psa_status_t psa_generic_hmac_setup_key(psa_algorithm_t hash_alg,
                                               uint8_t *block,
                                               size_t block_size,
                                               const uint8_t *key_buffer,
                                               size_t key_buffer_size)
{
    size_t dummy;

    if (key_buffer_size > block_size) {
        return psa_hash_compute(hash_alg, key_buffer, key_buffer_size, block,
                                block_size, &dummy);
    }

    memcpy(block, key_buffer, key_buffer_size);

    return PSA_SUCCESS;
}

static psa_status_t psa_generic_hmac_finish(psa_hash_operation_t *hash,
                                            psa_algorithm_t hash_alg,
                                            uint8_t *block,
                                            size_t block_size,
                                            uint8_t *buffer,
                                            size_t buffer_size)
{
    psa_status_t status;
    size_t hash_length;

    /* See step 4 in RFC 2104 */
    status = psa_hash_finish(hash, buffer, buffer_size, &hash_length);
    if (status != PSA_SUCCESS) {
        return status;
    }

    /* See step 5 in RFC 2104 */
    for (size_t i = 0; i < block_size; i++) {
        block[i] = block[i] ^ 0x5c;
    }

    /* See step 6 and 7 in RFC 2104 */
    status = psa_hash_setup(hash, hash_alg);
    if (status != PSA_SUCCESS) {
        return status;
    }

    status = psa_hash_update(hash, block, block_size);
    if (status != PSA_SUCCESS) {
        return status;
    }

    status = psa_hash_update(hash, buffer, hash_length);
    if (status != PSA_SUCCESS) {
        return status;
    }

    /* Clear key data */
    explicit_bzero(block, block_size);

    return PSA_SUCCESS;
}

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

psa_status_t psa_generic_hmac_setup(psa_hash_operation_t *hash,
                                    psa_algorithm_t hash_alg,
                                    const uint8_t *key_buffer,
                                    size_t key_buffer_size,
                                    uint8_t *buffer,
                                    size_t buffer_size)
{
    psa_status_t status;

    /* See step 1 in RFC 2104 */
    status = psa_generic_hmac_setup_key(hash_alg, buffer, buffer_size, key_buffer, key_buffer_size);
    if (status != PSA_SUCCESS) {
        /* Clear key data */
        explicit_bzero(buffer, buffer_size);
        return status;
    }

    status = psa_hash_setup(hash, hash_alg);
    if (status != PSA_SUCCESS) {
        /* Clear key data */
        explicit_bzero(buffer, buffer_size);
        return status;
    }

    /* See step 2 in RFC 2104 */
    for (size_t i = 0; i < buffer_size; i++) {
        buffer[i] = buffer[i] ^ 0x36;
    }

    /* See step 3 and 4 in RFC 2104 */
    status = psa_hash_update(hash, buffer, buffer_size);
    if (status != PSA_SUCCESS) {
        psa_hash_abort(hash);
        /* Clear key data */
        explicit_bzero(buffer, buffer_size);
        return status;
    }

    /* Undo the previous XOR operation to reuse the key later */
    for (size_t i = 0; i < buffer_size; i++) {
        buffer[i] = buffer[i] ^ 0x36;
    }

    return PSA_SUCCESS;
}

// TODO: Inline
psa_status_t psa_generic_hmac_update(psa_hash_operation_t *hash,
                                     const uint8_t *input,
                                     size_t input_length)
{
    return psa_hash_update(hash, input, input_length);
}

psa_status_t psa_generic_hmac_sign_finish(psa_hash_operation_t *hash,
                                          psa_algorithm_t hash_alg,
                                          uint8_t *mac,
                                          size_t mac_size,
                                          size_t *mac_length,
                                          uint8_t *buffer,
                                          size_t buffer_size)
{
    psa_status_t status;

    status = psa_generic_hmac_finish(hash, hash_alg, buffer, buffer_size, mac, mac_size);
    if (status != PSA_SUCCESS) {
        return status;
    }

    return psa_hash_finish(hash, mac, mac_size, mac_length);
}

psa_status_t psa_generic_hmac_verify_finish(psa_hash_operation_t *hash,
                                            psa_algorithm_t hash_alg,
                                            const uint8_t *mac,
                                            size_t mac_length,
                                            uint8_t *buffer,
                                            size_t buffer_size)
{
    (void)hash;
    (void)hash_alg;
    (void)mac;
    (void)mac_length;
    (void)buffer;
    (void)buffer_size;
    // TODO
    /*psa_status_t status;

    status = psa_generic_hmac_finish(hash, hash_alg, buffer, buffer_size, mac, mac_length);
    if (status != PSA_SUCCESS) {
        return status;
    }

    return psa_hash_verify(hash, mac, mac_length);*/

    return PSA_SUCCESS;
}

#ifdef __cplusplus
}
#endif

/**@}*/
