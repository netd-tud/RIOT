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
 * @brief       Glue code for the generic PSA Crypto HMAC MD5 implementation.
 *
 * @author      Armin Wolf <armin.wolf@mailbox.tu-dresden.de>
 *
 */

#ifdef __cplusplus
extern "C" {
#endif

#include "psa_mac.h"
#include "psa_crypto_generic_hmac.h"

psa_status_t psa_mac_compute_hmac_md5(const psa_key_attributes_t *attributes,
                                      const uint8_t *key_buffer,
                                      size_t key_buffer_size,
                                      const uint8_t *input,
                                      size_t input_length,
                                      uint8_t *mac,
                                      size_t mac_size,
                                      size_t *mac_length)
{
    uint8_t block[PSA_HASH_BLOCK_LENGTH(PSA_ALG_MD5)];
    (void)attributes;

    return psa_generic_hmac_compute(key_buffer, key_buffer_size,
                                    PSA_ALG_HMAC(PSA_ALG_MD5),
                                    input, input_length,
                                    mac, mac_size, mac_length,
                                    block);
}

psa_status_t psa_mac_verify_hmac_md5(const psa_key_attributes_t *attributes,
                                     const uint8_t *key_buffer,
                                     size_t key_buffer_size,
                                     const uint8_t *input,
                                     size_t input_length,
                                     const uint8_t *mac,
                                     size_t mac_length)
{
    uint8_t block[PSA_HASH_BLOCK_LENGTH(PSA_ALG_MD5)];
    (void)attributes;

    return psa_generic_hmac_verify(key_buffer, key_buffer_size,
                                   PSA_ALG_HMAC(PSA_ALG_MD5),
                                   input, input_length,
                                   mac, mac_length,
                                   block);
}

psa_status_t psa_mac_sign_setup_hmac_md5(psa_mac_operation_t *operation,
                                         const psa_key_attributes_t *attributes,
                                         const uint8_t *key_buffer,
                                         size_t key_buffer_size)
{
    (void)attributes;

    return psa_generic_hmac_setup(&operation->ctx.md5.hash,
                                  PSA_ALG_HMAC(PSA_ALG_MD5),
                                  key_buffer, key_buffer_size,
                                  operation->ctx.md5.block,
                                  sizeof(operation->ctx.md5.block));
}

psa_status_t psa_mac_verify_setup_hmac_md5(psa_mac_operation_t *operation,
                                           const psa_key_attributes_t *attributes,
                                           const uint8_t *key_buffer,
                                           size_t key_buffer_size)
{
    (void)attributes;

    return psa_generic_hmac_setup(&operation->ctx.md5.hash,
                                  PSA_ALG_HMAC(PSA_ALG_MD5),
                                  key_buffer, key_buffer_size,
                                  operation->ctx.md5.block,
                                  sizeof(operation->ctx.md5.block));
}

psa_status_t psa_mac_update_hmac_md5(psa_mac_operation_t *operation,
                                     const uint8_t *input,
                                     size_t input_length)
{
    return psa_generic_hmac_update(&operation->ctx.md5.hash,
                                   input, input_length);
}

psa_status_t psa_mac_sign_finish_hmac_md5(psa_mac_operation_t *operation,
                                          uint8_t *mac,
                                          size_t mac_size,
                                          size_t *mac_length)
{
    return psa_generic_hmac_sign_finish(&operation->ctx.md5.hash,
                                        PSA_ALG_HMAC(PSA_ALG_MD5),
                                        mac, mac_size, mac_length,
                                        operation->ctx.md5.block,
                                        sizeof(operation->ctx.md5.block));
}

psa_status_t psa_mac_verify_finish_hmac_md5(psa_mac_operation_t *operation,
                                            const uint8_t *mac,
                                            size_t mac_length)
{
    return psa_generic_hmac_verify_finish(&operation->ctx.md5.hash,
                                        PSA_ALG_HMAC(PSA_ALG_MD5),
                                        mac, mac_length,
                                        operation->ctx.md5.block,
                                        sizeof(operation->ctx.md5.block));
}

// TODO: Deduplicate
psa_status_t psa_mac_abort_hmac_md5(psa_mac_operation_t *operation)
{
    psa_status_t status;

    /* Clear key data */
    explicit_bzero(operation->ctx.md5.block, sizeof(operation->ctx.md5.block));
    status = psa_hash_abort(&operation->ctx.md5.hash);
    if (status != PSA_SUCCESS) {
        return status;
    }

    *operation = psa_mac_operation_init();

    return PSA_SUCCESS;
}

#ifdef __cplusplus
}
#endif

/**@}*/
