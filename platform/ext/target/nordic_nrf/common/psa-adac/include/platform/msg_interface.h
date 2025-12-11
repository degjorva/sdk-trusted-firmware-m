/*
 * SPDX-FileCopyrightText: Copyright The TrustedFirmware-M Contributors
 * Copyright (c) 2025, Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: BSD-3-Clause
 *
 */

#ifndef __PLATFORM_MSG_INTERFACE_H__
#define __PLATFORM_MSG_INTERFACE_H__

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

int msg_interface_init(void *transport, uint8_t *buffer, size_t buffer_size);
void msg_interface_free(void *transport);
int msg_interface_close(void *transport);

#ifdef __cplusplus
}
#endif

#endif /* __PLATFORM_MSG_INTERFACE_H__ */
