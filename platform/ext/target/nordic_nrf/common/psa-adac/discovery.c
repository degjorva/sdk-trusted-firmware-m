/*
 * SPDX-FileCopyrightText: Copyright The TrustedFirmware-M Contributors
 * Copyright (c) 2025, Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#include <stddef.h>
#include <stdint.h>

/* Discovery template for Nordic nRF platforms
 * This is a placeholder that should be customized for specific Nordic devices
 */
static uint8_t discovery_data[] = {
    /* Add discovery information here */
    0x00, 0x01, 0x02, 0x03  /* Placeholder data */
};

uint8_t discovery_template[] = {
    /* Discovery template data */
};

size_t discovery_template_len = sizeof(discovery_template);
