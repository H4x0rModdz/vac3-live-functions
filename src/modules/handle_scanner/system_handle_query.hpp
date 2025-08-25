#pragma once
#include <cstdint>

namespace vac::modules::handle_scanner {
    /**
     * @brief Query system handle information using obfuscated NtQuerySystemInformation
     *
     * This is the exact reverse of VAC's handle enumeration function.
     * Uses progressive buffer allocation and XOR obfuscation for API names.
     *
     * @param process_id_table Hash table for process ID lookups (max 500 entries)
     * @param max_process_count Maximum number of processes to track
     * @param unused_param Unused parameter (present in original)
     * @param unique_process_count Output: number of unique processes found
     * @param total_handle_count Output: total system handle count
     * @param handle_info_buffer Buffer for storing handle information per process
     * @return NTSTATUS code or error value
     */
    int __fastcall query_system_handle_information( uint32_t *process_id_table, int max_process_count, int unused_param,
                                                    uint32_t *unique_process_count, uint32_t *total_handle_count,
                                                    uint64_t *handle_info_buffer );
} // namespace vac::modules::handle_scanner