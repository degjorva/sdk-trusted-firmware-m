/*
 * Copyright (c) 2025 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "config_tfm.h"
#include "psa/crypto.h"
#include "psa/service.h"
#include "tfm_sp_log.h"

#ifdef PLATFORM_PSA_ADAC_SECURE_DEBUG
#include "psa_adac_platform.h"
#include <cracen/lib_kmu.h>
#endif

/* Key generation configuration */
#define ADAC_MAX_KEY_GENERATIONS 4
#define ADAC_ROTPK_SIZE 32
#define ADAC_KMU_SLOT_SIZE 16  /* CRACEN_KMU_SLOT_KEY_SIZE */
#define ADAC_SLOTS_PER_KEY (ADAC_ROTPK_SIZE / ADAC_KMU_SLOT_SIZE)  /* 2 slots per Ed25519 key */

/* KMU slot layout: slots 207-214 for 4 generations (configurable via Kconfig) */
#ifndef TFM_ADAC_ROTPK_KMU_SLOT_BASE
#define TFM_ADAC_ROTPK_KMU_SLOT_BASE 207
#endif /* TFM_ADAC_ROTPK_KMU_SLOT_BASE */

/* Calculate KMU slot for a generation: gen 0 = 207, gen 1 = 209, gen 2 = 211, gen 3 = 213 */
#define ADAC_GEN_TO_KMU_SLOT(gen) (TFM_ADAC_ROTPK_KMU_SLOT_BASE + (gen) * ADAC_SLOTS_PER_KEY)

/* PSA Key ID = 0x7FFF0000 | (usage_scheme << 12) | slot_id. RAW scheme = 3. */
#define ADAC_ROTPK_PSA_KEY_ID(slot) (0x7FFF0000 | (3 << 12) | ((slot) & 0xFF))

/* Initial minimum key generation from Kconfig (default 0) */
#ifndef TFM_ADAC_AUTH_KEY_GEN
#define TFM_ADAC_AUTH_KEY_GEN 0
#endif

/* Auto-revoke older generations on successful auth (default enabled) */
#ifndef TFM_ADAC_AUTO_REVOKE
#define TFM_ADAC_AUTO_REVOKE 1
#endif

/* Track which generation was used for successful authentication */
static int8_t adac_authenticated_generation = -1;

#ifdef PLATFORM_PSA_ADAC_SECURE_DEBUG

/**
 * @brief Check if a KMU slot is revoked
 *
 * @param slot_id KMU slot ID
 * @return true if revoked, false if available or empty
 */
static bool adac_is_kmu_slot_revoked(int slot_id)
{
    uint32_t metadata;
    int status = lib_kmu_read_metadata(slot_id, &metadata);
    return (status == -LIB_KMU_REVOKED);
}

/**
 * @brief Check if a generation's KMU slots are revoked
 *
 * @param gen Generation index (0-3)
 * @return true if revoked, false otherwise
 */
static bool adac_is_generation_revoked(uint8_t gen)
{
    if (gen >= ADAC_MAX_KEY_GENERATIONS) {
        return true;
    }
    int slot = ADAC_GEN_TO_KMU_SLOT(gen);
    return adac_is_kmu_slot_revoked(slot);
}

/**
 * @brief Revoke all generations less than the specified generation
 *
 * @param current_gen The current generation (generations < this will be revoked)
 * @return 0 on success, negative on error
 */
static int adac_revoke_older_generations(uint8_t current_gen)
{
    int errors = 0;

    for (uint8_t gen = 0; gen < current_gen && gen < ADAC_MAX_KEY_GENERATIONS; gen++) {
        int base_slot = ADAC_GEN_TO_KMU_SLOT(gen);

        /* Revoke both slots for this generation's key */
        for (int i = 0; i < ADAC_SLOTS_PER_KEY; i++) {
            int slot = base_slot + i;

            /* Skip if already revoked or empty */
            if (lib_kmu_is_slot_empty(slot)) {
                continue;
            }
            if (adac_is_kmu_slot_revoked(slot)) {
                continue;
            }

            LOG_INFFMT("[ADAC] Revoking KMU slot %d (gen %d)\r\n", slot, gen);
            int status = lib_kmu_revoke_slot(slot);
            if (status != LIB_KMU_SUCCESS) {
                LOG_INFFMT("[ADAC] Failed to revoke slot %d (status=%d)\r\n", slot, status);
                errors++;
            }
        }
    }

    return errors > 0 ? -1 : 0;
}

/**
 * @brief Read a ROTPK from KMU slots
 *
 * @param gen Generation index (0-3)
 * @param rotpk Output buffer for the ROTPK (32 bytes)
 * @return 0 on success, negative on error
 */
static int adac_read_rotpk_from_kmu(uint8_t gen, uint8_t *rotpk)
{
    psa_status_t status;
    size_t key_length;
    int slot = ADAC_GEN_TO_KMU_SLOT(gen);
    psa_key_id_t key_id = ADAC_ROTPK_PSA_KEY_ID(slot);

    /* Check if slot is revoked */
    if (adac_is_generation_revoked(gen)) {
        return -1;
    }

    /* Check if slot is empty */
    if (lib_kmu_is_slot_empty(slot)) {
        return -1;
    }

    LOG_INFFMT("[ADAC] Exporting key id=0x%x slot=%d\r\n",
               (unsigned int)key_id, slot);

    /* Use psa_export_key for public keys (not psa_export_public_key which is for key pairs) */
    status = psa_export_key(key_id, rotpk, ADAC_ROTPK_SIZE, &key_length);

    if (status != PSA_SUCCESS) {
        LOG_INFFMT("[ADAC] psa_export_key failed: %d\r\n", (int)status);
        return -1;
    }

    if (key_length != ADAC_ROTPK_SIZE) {
        LOG_INFFMT("[ADAC] Wrong key size: %d (expected %d)\r\n",
                   (int)key_length, ADAC_ROTPK_SIZE);
        return -1;
    }

    return 0;
}

/**
 * @brief Load all non-revoked ROTPKs from KMU
 *
 * @param rotpks Output array of ROTPKs
 * @param generations Output array of generation indices for each loaded key
 * @param count Output: number of keys loaded
 * @return 0 on success
 */
static int adac_load_rotpks(uint8_t rotpks[][ADAC_ROTPK_SIZE],
                            uint8_t *generations,
                            uint8_t *count)
{
    *count = 0;

    for (uint8_t gen = 0; gen < ADAC_MAX_KEY_GENERATIONS; gen++) {
        int slot = ADAC_GEN_TO_KMU_SLOT(gen);

        /* Skip revoked generations */
        if (adac_is_generation_revoked(gen)) {
            LOG_INFFMT("[ADAC] Gen %d: revoked\r\n", gen);
            continue;
        }

        /* Check if slot is provisioned */
        if (lib_kmu_is_slot_empty(slot)) {
            LOG_INFFMT("[ADAC] Gen %d: not provisioned (slot %d empty)\r\n", gen, slot);
            continue;
        }

        /* Try to read from KMU */
        if (adac_read_rotpk_from_kmu(gen, rotpks[*count]) == 0) {
            LOG_INFFMT("[ADAC] Gen %d: loaded from KMU slot %d\r\n", gen, slot);
            generations[*count] = gen;
            (*count)++;
        } else {
            LOG_INFFMT("[ADAC] Gen %d: failed to read from KMU slot %d\r\n", gen, slot);
        }
    }

    return 0;
}

#endif /* PLATFORM_PSA_ADAC_SECURE_DEBUG */

/**
 * @brief Get the generation that was used for successful authentication
 *
 * @return Generation index (0-3), or -1 if not authenticated
 */
int8_t adac_get_authenticated_generation(void)
{
    return adac_authenticated_generation;
}

/**
 * @brief Set the authenticated generation (called from platform code)
 *
 * @param gen Generation index (0-3)
 */
void adac_set_authenticated_generation(int8_t gen)
{
    adac_authenticated_generation = gen;
}

/**
 * @brief Perform post-authentication actions (revoke older generations)
 *
 * Called after successful authentication to revoke older key generations.
 */
void adac_post_auth_actions(void)
{
#ifdef PLATFORM_PSA_ADAC_SECURE_DEBUG
#if TFM_ADAC_AUTO_REVOKE
    if (adac_authenticated_generation > 0) {
        LOG_INFFMT("[ADAC] Auto-revoking generations < %d\r\n",
                   adac_authenticated_generation);
        adac_revoke_older_generations(adac_authenticated_generation);
    }
#endif
#endif
}

psa_status_t tfm_adac_init(void)
{
#ifdef PLATFORM_PSA_ADAC_SECURE_DEBUG
    int ret;
    psa_status_t psa_status;
    uint8_t rotpks[ADAC_MAX_KEY_GENERATIONS][ADAC_ROTPK_SIZE];
    uint8_t generations[ADAC_MAX_KEY_GENERATIONS];
    uint8_t count = 0;

    LOG_INFFMT("[ADAC] Initializing (max %d generations, base slot %d)\r\n",
               ADAC_MAX_KEY_GENERATIONS, TFM_ADAC_ROTPK_KMU_SLOT_BASE);

    /* Initialize PSA crypto before using any crypto functions */
    psa_status = psa_crypto_init();
    if (psa_status != PSA_SUCCESS) {
        LOG_INFFMT("[ADAC] psa_crypto_init failed: %d\r\n", (int)psa_status);
        return psa_status;
    }

    /* Apply initial revocation from config */
#if TFM_ADAC_AUTH_KEY_GEN > 0
    LOG_INFFMT("[ADAC] Initial revocation: generations < %d\r\n", TFM_ADAC_AUTH_KEY_GEN);
    adac_revoke_older_generations(TFM_ADAC_AUTH_KEY_GEN);
#endif

    /* Load all available ROTPKs from KMU */
    adac_load_rotpks(rotpks, generations, &count);

    if (count == 0) {
        LOG_INFFMT("[ADAC] No valid ROTPKs found - provision keys to KMU slots %d-%d\r\n",
                   TFM_ADAC_ROTPK_KMU_SLOT_BASE,
                   TFM_ADAC_ROTPK_KMU_SLOT_BASE + (ADAC_MAX_KEY_GENERATIONS * ADAC_SLOTS_PER_KEY) - 1);
        return PSA_SUCCESS;
    }

    LOG_INFFMT("[ADAC] Loaded %d ROTPKs\r\n", count);

    /* Call the platform ADAC handler with all available keys */
    ret = tfm_to_psa_adac_nordic_secure_debug_multigen(
        rotpks, generations, count, ADAC_ROTPK_SIZE);

    if (ret == 0) {
        LOG_INFFMT("[ADAC] Debug unlocked (gen %d)\r\n",
                   adac_authenticated_generation);
        adac_post_auth_actions();
    }
#endif
    return PSA_SUCCESS;
}

/* Dummy service to satisfy TF-M partition requirement */
psa_status_t tfm_adac_service_sfn(const psa_msg_t *msg)
{
    (void)msg;
    return PSA_ERROR_NOT_SUPPORTED;
}
