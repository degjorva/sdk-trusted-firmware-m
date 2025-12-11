#-------------------------------------------------------------------------------
# Copyright (c) 2021-2022, Arm Limited. All rights reserved.
# Copyright (c) 2022 Cypress Semiconductor Corporation (an Infineon company)
# or an affiliate of Cypress Semiconductor Corporation. All rights reserved.
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------

# Set default git remote if not specified
if(NOT DEFINED PLATFORM_PSA_ADAC_GIT_REMOTE)
    set(PLATFORM_PSA_ADAC_GIT_REMOTE "https://git.trustedfirmware.org/shared/psa-adac.git")
endif()

# Ensure variables are strings, not lists
string(STRIP "${PLATFORM_PSA_ADAC_VERSION}" _PSA_ADAC_VERSION)
string(STRIP "${PLATFORM_PSA_ADAC_GIT_REMOTE}" _PSA_ADAC_GIT_REMOTE)

fetch_remote_library(
    LIB_NAME                libpsaadac
    LIB_SOURCE_PATH_VAR     PLATFORM_PSA_ADAC_SOURCE_PATH
    LIB_BINARY_PATH_VAR     PLATFORM_PSA_ADAC_BUILD_PATH
    FETCH_CONTENT_ARGS
        GIT_TAG             "${_PSA_ADAC_VERSION}"
        GIT_REPOSITORY      "${_PSA_ADAC_GIT_REMOTE}"
)

if (NOT LIB_BINARY_PATH_VAR)
set(PLATFORM_PSA_ADAC_BUILD_PATH "${CMAKE_SOURCE_DIR}/build/lib/ext/libpsaadac-build" CACHE PATH "Path to build directory of psa-adac.")
endif()

set(PSA_ADAC_TARGET "trusted-firmware-m")

# For NCS builds, use nrf_security and oberon-psa-crypto headers instead of raw mbedtls
# Raw mbedtls headers have alt includes that don't exist in NCS builds
if(DEFINED ZEPHYR_NRF_MODULE_DIR)
    # NCS build - use properly configured crypto interfaces:
    # 1. Generated PSA interface for proper config (nrf-config.h)
    # 2. oberon-psa-crypto for PSA Crypto API
    # 3. mbedtls tests/include/alt-dummy for dummy alt headers (ecjpake_alt.h etc.)
    # 4. mbedtls/include for mbedtls headers (private_access.h etc.)
    # 5. nrf_security for utils
    set(PSA_ADAC_MBEDTLS_INCLUDE
        "${CMAKE_BINARY_DIR}/../generated/interface_nrf_security_psa"
        "${ZEPHYR_NRF_MODULE_DIR}/../modules/crypto/oberon-psa-crypto/include"
        "${ZEPHYR_NRF_MODULE_DIR}/../modules/crypto/mbedtls/tests/include/alt-dummy"
        "${ZEPHYR_NRF_MODULE_DIR}/../modules/crypto/mbedtls/include"
        "${ZEPHYR_NRF_MODULE_DIR}/subsys/nrf_security/include"
        "${ZEPHYR_NRF_MODULE_DIR}/subsys/nrf_security/src/utils"
    )
    # Override TFM_PLATFORM to use PSA-ADAC's internal Nordic platform
    set(TFM_PLATFORM "ext/nordic/nrf54l15")
else()
    set(PSA_ADAC_MBEDTLS_INCLUDE "${MBEDCRYPTO_PATH}/include")
endif()

set(PSA_ADAC_TOOLCHAIN    FALSE    CACHE BOOL "Whether to use psa-adac toolchain." FORCE)

add_subdirectory(${PLATFORM_PSA_ADAC_SOURCE_PATH} ${PLATFORM_PSA_ADAC_BUILD_PATH})
