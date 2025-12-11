/*
 * SPDX-FileCopyrightText: Copyright The TrustedFirmware-M Contributors
 * Copyright (c) 2025, Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include "psa_adac_config.h"
#include "psa_adac_debug.h"
#include "psa_adac_sda.h"
#include "psa_adac.h"
#include "platform/platform.h"
#include "platform/msg_interface.h"
/* Required for crypto_hw_apply_debug_permissions, the only API required
 * by ADAC which is not standardized through PSA Crypto but through the
 * TF-M specific crypto_hw.h header
 */
#include "crypto_hw.h"

#include <string.h>

#define ROTPK_ANCHOR_ALG PSA_ALG_SHA_512

/* Maximum number of key generations supported */
#define MAX_ROTPK_ANCHORS 4

extern uint8_t discovery_template[];
extern size_t discovery_template_len;

static uint8_t buffer[512];
static uint8_t messages[512];
static uint8_t *rotpk_anchors[MAX_ROTPK_ANCHORS];
static size_t rotpk_anchors_size[MAX_ROTPK_ANCHORS];
static uint8_t rotpk_anchors_type[MAX_ROTPK_ANCHORS];
static size_t rotpk_anchors_length = 0;

/* Generation indices corresponding to each ROTPK anchor */
static uint8_t rotpk_generations[MAX_ROTPK_ANCHORS];

/* Track the certificate generation from the last verified certificate */
static int8_t last_cert_generation = -1;

/* External functions from tfm_adac.c for generation tracking */
extern void adac_set_authenticated_generation(int8_t gen);
extern int8_t adac_get_authenticated_generation(void);

void psa_adac_platform_init(void)
{
    /* Platform initialization for Nordic */
}

size_t psa_adac_platform_discovery(uint8_t *reply, size_t reply_size)
{
    if (reply_size >= discovery_template_len) {
        memcpy(reply, discovery_template, discovery_template_len);
        return discovery_template_len;
    }
    return 0;
}

void psa_adac_close_session(void)
{
    (void)msg_interface_close(NULL);
}

void psa_adac_resume(void)
{
    /* Perform the same actions as the close session command, as specified */
    (void)msg_interface_close(NULL);
}

void psa_adac_platform_lock(void)
{
    /* Lock platform for secure debug */
}

adac_status_t psa_adac_change_life_cycle_state(uint8_t *input, size_t input_size)
{
    /* LCS change is platform specific and is NOT implemented */
    /* Ignore return value and send UNSUPPORTED status for now */
    (void)input;
    (void)input_size;
    return ADAC_UNSUPPORTED;
}

int psa_adac_platform_check_token(uint8_t *token, size_t token_size)
{
    /* Token validation can be implemented here */
    (void)token;
    (void)token_size;
    return 0;
}

#define ED25519_PUBKEY_SIZE 32

/**
 * @brief Platform-specific certificate check
 *
 * Determines the key generation by matching the certificate's public key
 * against our loaded ROTPKs.
 *
 * @param crt Certificate data
 * @param crt_size Certificate size
 * @return 0 on success, non-zero if certificate is rejected
 */
int psa_adac_platform_check_certificate(uint8_t *crt, size_t crt_size)
{
    if (crt_size < sizeof(certificate_header_t) + ED25519_PUBKEY_SIZE) {
        PSA_ADAC_LOG_ERR("platform", "Certificate too small\r\n");
        return -1;
    }

    /* Extract public key from certificate (immediately follows header) */
    uint8_t *cert_pubkey = crt + sizeof(certificate_header_t);

    /* Find which ROTPK matches this certificate's public key */
    for (size_t i = 0; i < rotpk_anchors_length; i++) {
        if (rotpk_anchors_size[i] == ED25519_PUBKEY_SIZE &&
            memcmp(rotpk_anchors[i], cert_pubkey, ED25519_PUBKEY_SIZE) == 0) {
            /* Found matching ROTPK - use its generation */
            last_cert_generation = rotpk_generations[i];
            PSA_ADAC_LOG_DEBUG("platform", "Certificate matches ROTPK[%d], generation %d\r\n",
                              (int)i, last_cert_generation);
            return 0;
        }
    }

    /* No matching ROTPK found - this shouldn't happen if signature verified */
    PSA_ADAC_LOG_ERR("platform", "Certificate public key not in ROTPK list\r\n");
    return -1;
}

int psa_adac_apply_permissions(uint8_t permissions_mask[16])
{
    int ret = crypto_hw_apply_debug_permissions(permissions_mask, 16);
    if (ret) {
        PSA_ADAC_LOG_ERR("platform", "psa_adac_to_tfm_apply_permissions "
                          "failed\r\n");
        return ret;
    }

    PSA_ADAC_LOG_INFO("platform",
                      "\r\nNordic platform unlocked for secure debug\r\n");
    return ret;
}

/**
 * @brief Legacy single-key ADAC handler (for backwards compatibility)
 */
int tfm_to_psa_adac_nordic_secure_debug(uint8_t *secure_debug_rotpk, uint32_t len)
{
    uint8_t generation = 0;
    return tfm_to_psa_adac_nordic_secure_debug_multigen(
        (uint8_t (*)[32])secure_debug_rotpk, &generation, 1, len);
}

/**
 * @brief Multi-generation ADAC handler
 *
 * @param rotpks Array of ROTPK buffers (32 bytes each)
 * @param generations Array of generation indices for each ROTPK
 * @param count Number of ROTPKs
 * @param key_size Size of each ROTPK (should be 32)
 * @return 0 on success, -1 on failure
 */
int tfm_to_psa_adac_nordic_secure_debug_multigen(
    uint8_t rotpks[][32],
    uint8_t *generations,
    uint8_t count,
    uint32_t key_size)
{
    authentication_context_t auth_ctx;
    int ret = -1;

    if (count == 0 || count > MAX_ROTPK_ANCHORS) {
        PSA_ADAC_LOG_ERR("main", "Invalid ROTPK count: %d\r\n", count);
        return -1;
    }

    PSA_ADAC_LOG_INFO("main", "%s: %d ROTPKs\r\n", __func__, count);

    if (psa_adac_detect_debug_request()) {
        PSA_ADAC_LOG_INFO("main", "ADAC: Debug request detected\r\n");

        msg_interface_init(NULL, messages, sizeof(messages));

        psa_adac_init();
        psa_adac_acknowledge_debug_request();

        /* Set up ROTPK anchors for all provided keys */
        rotpk_anchors_length = count;
        for (uint8_t i = 0; i < count; i++) {
            rotpk_anchors[i] = rotpks[i];
            rotpk_anchors_size[i] = key_size;
            rotpk_anchors_type[i] = ED_25519_SHA512;
            rotpk_generations[i] = generations[i];

            PSA_ADAC_LOG_DEBUG("main", "ROTPK[%d]: gen=%d\r\n", i, generations[i]);
        }

        /* Initialize authentication context with all ROTPKs */
        authentication_context_init(&auth_ctx, buffer, sizeof(buffer), ROTPK_ANCHOR_ALG,
                                    rotpk_anchors, rotpk_anchors_size, rotpk_anchors_type,
                                    rotpk_anchors_length);

        PSA_ADAC_LOG_INFO("main", "Starting authentication.\r\n");

        /* Reset generation tracking */
        last_cert_generation = -1;

        authentication_handle(&auth_ctx);

        PSA_ADAC_LOG_INFO("main", "Authentication is a %s\r\n",
                          auth_ctx.state == AUTH_SUCCESS ? "success" : "failure");

        if (auth_ctx.state == AUTH_SUCCESS) {
            ret = 0;

            /* Store the authenticated generation for post-auth actions */
            if (last_cert_generation >= 0) {
                adac_set_authenticated_generation(last_cert_generation);
                PSA_ADAC_LOG_INFO("main", "Authenticated with generation %d\r\n",
                                  last_cert_generation);
            }
        }

        authentication_context_content_clear(&auth_ctx);
        msg_interface_free(NULL);
    } else {
        PSA_ADAC_LOG_INFO("main", "No secure debug connection.\r\n");
    }

    return ret;
}

void platform_init(void)
{
    /* Platform initialization */
}

int msg_interface_init(void *transport, uint8_t *buffer, size_t buffer_size)
{
    (void)transport;
    (void)buffer;
    (void)buffer_size;
    /* Initialize message interface using CTRL-AP mailbox */
    return 0;
}

void msg_interface_free(void *transport)
{
    (void)transport;
    /* Free message interface resources */
}

int msg_interface_close(void *transport)
{
    (void)transport;
    /* Close message interface */
    return 0;
}
