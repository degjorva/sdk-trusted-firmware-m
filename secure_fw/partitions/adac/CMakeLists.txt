#-------------------------------------------------------------------------------
# Copyright (c) 2025 Nordic Semiconductor ASA
#
# SPDX-License-Identifier: BSD-3-Clause
#
#-------------------------------------------------------------------------------

if (NOT TFM_PARTITION_ADAC)
    return()
endif()

cmake_minimum_required(VERSION 3.21)

add_library(tfm_psa_rot_partition_adac STATIC)

add_dependencies(tfm_psa_rot_partition_adac manifest_tool)

target_sources(tfm_psa_rot_partition_adac
    PRIVATE
        tfm_adac.c
        ${CMAKE_BINARY_DIR}/generated/secure_fw/partitions/adac/auto_generated/intermedia_tfm_adac.c
)

target_sources(tfm_partitions
    INTERFACE
        ${CMAKE_BINARY_DIR}/generated/secure_fw/partitions/adac/auto_generated/load_info_tfm_adac.c
)

target_include_directories(tfm_psa_rot_partition_adac
    PRIVATE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        ${CMAKE_BINARY_DIR}/generated/secure_fw/partitions/adac
)

target_include_directories(tfm_partitions
    INTERFACE
        ${CMAKE_BINARY_DIR}/generated/secure_fw/partitions/adac
)

target_link_libraries(tfm_psa_rot_partition_adac
    PRIVATE
        platform_s
        tfm_config
        tfm_sprt
        psa_crypto_config
)

# Include PSA-ADAC headers when enabled
# Note: We link to platform_s which already links to trusted-firmware-m-psa-adac
# Do not link psa-adac directly to avoid recompiling PUBLIC sources
if(PLATFORM_PSA_ADAC_SECURE_DEBUG)
    # PSA-ADAC source path is set by lib/ext/psa-adac/CMakeLists.txt
    target_include_directories(tfm_psa_rot_partition_adac
        PRIVATE
            ${CMAKE_SOURCE_DIR}/platform/ext/target/nordic_nrf/common/psa-adac/include
            ${PLATFORM_PSA_ADAC_SOURCE_PATH}/psa-adac/core/include
            # CRACEN KMU library headers (for lib_kmu.h)
            ${ZEPHYR_NRF_MODULE_DIR}/subsys/nrf_security/src/drivers/cracen/common/include
    )
endif()

############################ Partition Defs ####################################

target_link_libraries(tfm_partitions
    INTERFACE
        tfm_psa_rot_partition_adac
)

target_compile_definitions(tfm_config
    INTERFACE
        TFM_PARTITION_ADAC
)

# Pass KMU configuration to the partition
if(DEFINED TFM_ADAC_ROTPK_KMU_SLOT)
    target_compile_definitions(tfm_psa_rot_partition_adac
        PRIVATE
            TFM_ADAC_ROTPK_KMU_SLOT=${TFM_ADAC_ROTPK_KMU_SLOT}
    )
endif()
