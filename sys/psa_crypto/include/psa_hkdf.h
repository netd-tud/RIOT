/*
 * Copyright (C) 2024 TU Dresden
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     sys_psa_crypto
 * @defgroup    sys_psa_crypto_hkdf PSA KDF
 * @{
 *
 * @file        psa_hmac.h
 * @brief       Function declarations for PSA Crypto HKDF implementation.
 *
 * @author      Daria Zatokovenko <daria.zatokovenko@mailbox.tu-dresden.de>
 *
 * @}
 */

#ifndef PSA_HKDF_H
#define PSA_HKDF_H

#ifdef __cplusplus
extern "C" {
#endif

#include "kernel_defines.h"

#include <psa/crypto.h>
#include "psa/crypto_contexts.h"

#include <psa/crypto_types.h>
#include <psa/crypto_struct.h>

#include "psa_crypto_slot_management.h"


/**
 * @brief   Structure containing the HKDF key derivation context.
 */
typedef struct {
    uint8_t *salt;              /**< Salt value for the HKDF operation. */
    size_t salt_length;         /**< Length of the salt value. */
    uint8_t *ikm;               /**< Input keying material for the HKDF operation. */
    size_t ikm_length;          /**< Length of the input keying material. */
    uint8_t *info;              /**< Non-secret value that is used in the expansion phase. */
    size_t info_length;         /**< Length of the info. */
    uint8_t *prk;               /**< Buffer to hold the pseudorandom key (PRK). */
    size_t prk_length;          /**< Length of the pseudorandom key. */
    psa_algorithm_t hash_alg;   /**< Hash algorithm used in the HKDF operation. */
    size_t hash_length;         /**< Length of the hash. */
} psa_hkdf_key_derivation_ctx_t;

/**
 * @brief   Low level function to pass direct input to the key derivation operation
 *          See @ref psa_key_derivation_input_bytes()
 * @param operation
 * @param step
 * @param data
 * @param data_length
 * @param alg
 * @return psa_status_t
 */
psa_status_t psa_hkdf_input_bytes(psa_key_derivation_operation_t *operation,
                                  psa_key_derivation_step_t step,
                                  const uint8_t *data,
                                  size_t data_length,
                                  psa_algorithm_t alg);

psa_status_t psa_hkdf_input_key(psa_key_derivation_operation_t *operation,
                                psa_key_derivation_step_t step,
                                psa_key_type_t key_type,
                                const uint8_t *data,
                                size_t data_length,
                                psa_algorithm_t alg);

psa_status_t psa_hkdf_output_bytes(psa_key_derivation_operation_t *operation,
                                   uint8_t *output,
                                   size_t output_length,
                                   psa_algorithm_t alg);

psa_status_t psa_hkdf_output_key(psa_key_derivation_operation_t *operation,
                                 const psa_key_attributes_t *attributes,
                                 psa_key_id_t *key);

psa_status_t psa_generate_derived_key(psa_key_slot_t *slot,
                                      size_t bits,
                                      psa_key_derivation_operation_t *operation,
                                      psa_key_id_t *key);

psa_status_t hkdf_extract(psa_key_derivation_operation_t *operation,
                          const uint8_t *ikm, size_t ikm_length,
                          const uint8_t *salt, size_t salt_length);

psa_status_t hkdf_expand(psa_key_derivation_operation_t *operation,
                         uint8_t *output, size_t output_length);

bool is_valid_step_for_current_state(operation_state_t state,
                                     psa_key_derivation_step_t step);

#ifdef __cplusplus
}
#endif

#endif /* PSA_KDF_H */
/**@}*/
