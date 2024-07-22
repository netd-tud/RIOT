/*
 * Copyright (C) 2024 TU Dresden
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     sys_psa_crypto
 * @defgroup    sys_psa_crypto_hmac  PSA KDF
 * @{
 *
 * @file        psa_hmac.h
 * @brief       Function declarations for generic PSA Crypto KDF implementation.
 *
 * @author      Daria Zatokovenko <daria.zatokovenko@mailbox.tu-dresden.de>
 *
 * @}
 */


#ifndef PSA_KEY_DERIVATION_H
#define PSA_KEY_DERIVATION_H

#ifdef __cplusplus
extern "C" {
#endif

#include "kernel_defines.h"
#include "psa/crypto.h"
#include "psa/crypto_contexts.h"

/**
 * @brief   Low level function to abort the key derivation operation
 *          See @ref psa_kdf_abort()
 * @param   operation
 * @return  @ref psa_status_t
 */
psa_status_t psa_kdf_abort(psa_key_derivation_operation_t *operation);

#ifdef __cplusplus
}
#endif


#endif /* PSA_KEY_DERIVATION_H */
/**@}*/

