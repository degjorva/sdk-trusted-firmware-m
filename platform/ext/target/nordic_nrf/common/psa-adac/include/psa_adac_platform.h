/*
 * SPDX-FileCopyrightText: Copyright The TrustedFirmware-M Contributors
 * Copyright (c) 2025, Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef __PSA_ADAC_PLATFORM_H__
#define __PSA_ADAC_PLATFORM_H__

#include "psa_adac_config.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PSA_ADAC_PLATFORM_BANNER "PSA ADAC: Nordic nRF TF-M"

/* Use CTRL-AP mailbox for secure debug communication */
#define NORDIC_CTRLAP_BASE        (0x50042000UL)
#define NORDIC_CTRLAP_SIZE        (0x1000)
#define SDM_MEMORY_WINDOW_BASE    NORDIC_CTRLAP_BASE
#define SDM_MEMORY_WINDOW_SIZE    NORDIC_CTRLAP_SIZE
#define PSA_ADAC_TRANSPORT_OWN_MEMORY
#define PSA_ADAC_AUTHENTICATOR_IMPLICIT_TRANSPORT

#define tfm_to_psa_adac_platform_secure_debug tfm_to_psa_adac_nordic_secure_debug


/*
 * From tf-m to psa-adac.
 * Call to this function will wait for host debugger to initiate the
 * secure debug connection and will perform the secure debug authentication
 * process.
 */
int tfm_to_psa_adac_nordic_secure_debug(uint8_t *secure_debug_rotpk, uint32_t len);

/*
 * Multi-generation ADAC authentication.
 * Supports multiple ROTPKs for key rotation and revocation.
 *
 * @param rotpks Array of ROTPK buffers (32 bytes each)
 * @param generations Array of generation indices for each ROTPK
 * @param count Number of ROTPKs (1-4)
 * @param key_size Size of each ROTPK in bytes (should be 32)
 * @return 0 on success, -1 on failure
 */
int tfm_to_psa_adac_nordic_secure_debug_multigen(
    uint8_t rotpks[][32],
    uint8_t *generations,
    uint8_t count,
    uint32_t key_size);

#ifdef __cplusplus
}
#endif

#endif /* __PSA_ADAC_PLATFORM_H__ */
