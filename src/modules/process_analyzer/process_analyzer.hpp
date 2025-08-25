#pragma once

#include "../../common/types.hpp"

namespace vac::modules::process_analyzer {
    /**
     * @brief Global system info structure
     *
     * This structure contains system information used by VAC for compatibility checks.
     *
     * Key fields:
     * - data[12]: Minor OS version (used for API compatibility)
     * - data[15]: Major OS version (2 = Windows Vista/7/8/10/11)
     *
     * Usage in VAC code:
     * if ((g_system_info.data[15] != 2 || g_system_info.data[12] < 6) && ...)
     * This checks for Windows Vista+ (6.0+) before using newer APIs.
     */
    inline struct system_info_t {
        uint32_t data[ 20 ]; ///< System information array

        /**
         * @brief Initialize with default Windows 10+ values
         */
        void initialize_default( ) {
            memset( data, 0, sizeof( data ) );
            data[ 12 ] = 6; // Minor version (Windows 6.0+)
            data[ 15 ] = 2; // Major version indicator
        }

        /**
         * @brief Check if system supports newer process APIs
         * @return true if system supports PROCESS_QUERY_LIMITED_INFORMATION
         */
        [[nodiscard]] bool supports_limited_query_info( ) const {
            return ( data[ 15 ] == 2 && data[ 12 ] >= 6 );
        }
    } g_system_info = { };

    /**
     * @brief Analyze single process for information gathering
     *
     * This function performs comprehensive analysis of a single process, including:
     *
     * 1. PROCESS ACCESS:
     *    - Attempts OpenProcess with PROCESS_QUERY_INFORMATION (4096)
     *    - Falls back to PROCESS_QUERY_LIMITED_INFORMATION (1024) on older Windows
     *    - Handles access denied errors and marks failed attempts
     *
     * 2. PROCESS INFORMATION GATHERING:
     *    - Gets process image file name using GetProcessImageFileNameW
     *    - Normalizes the process path (drive letter conversion)
     *    - Retrieves process timing information (creation, exit, user, kernel time)
     *    - Calculates process uptime in seconds
     *
     * 3. PATH PROCESSING:
     *    - Extracts directory path from full process path
     *    - Converts Unicode paths to ANSI for storage
     *    - Separates filename from directory path
     *
     * 4. HASH GENERATION AND STORAGE:
     *    - Calculates hash of full process path using VAC's hash algorithm
     *    - Calculates hash of directory path separately
     *    - Stores string data in hash tables with reference counting
     *    - Updates lookup arrays for fast hash-based searches
     *
     * 5. PROCESS ENTRY CREATION:
     *    - Creates 28-byte process entry in analysis buffer
     *    - Stores process ID, hashes, timing, and flags
     *    - Maintains process count and buffer management
     *
     * @param analysis_context Pointer to process analysis context structure
     *                        Contains analysis buffer, flags, and configuration
     * @param process_id Process ID to analyze
     * @param access_flags Access flags for OpenProcess call (usually PROCESS_QUERY_INFORMATION)
     * @param parent_process_id Parent process ID (for relationship tracking)
     * @param handle_info Handle information from system handle enumeration
     * @param additional_flags Additional process flags for classification
     *
     * @return 1 on success (process analyzed and entry created)
     * @return 0 on failure (insufficient buffer space)
     * @return 1 on skip (terminated process when include_terminated is false)
     *
     * @note This function directly modifies the analysis_context->analysis_buffer
     *       and increments the process count at offset +36 in the buffer.
     */
    char analyze_process_entry( common::process_analysis_context_t *analysis_context, uint32_t process_id, uint32_t access_flags,
                                           uint32_t parent_process_id, uint32_t handle_info, uint32_t additional_flags );

} // namespace vac::modules::process_analyzer