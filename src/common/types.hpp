#pragma once

#include <array>
#include <cstdint>
#include <windows.h>
#include <winternl.h>

namespace vac::common {
    /**
     * @brief System handle information structure from ntdll
     */
    struct system_handle_t {
        ULONG  m_process_id        = { }; ///< Process ID that owns this handle
        UCHAR  m_object_type_index = { }; ///< Type of object (file, process, thread, etc.)
        UCHAR  m_handle_attributes = { }; ///< Handle attributes and flags
        USHORT m_handle_value      = { }; ///< Handle value within the process
        PVOID  m_object_pointer    = { }; ///< Kernel object pointer
        ULONG  m_granted_access    = { }; ///< Access rights granted to this handle
    };

    /**
     * @brief System handle information response structure
     */
    struct system_handle_information_t {
        ULONG           m_handle_count = { }; ///< Total number of handles in system
        system_handle_t m_handles[ 1 ] = { }; ///< Variable length array of handles
    };

    /**
     * @brief Process entry structure (28 bytes)
     */
    struct process_entry_t {
        uint32_t m_hash_name         = { }; ///< Hash of process name
        uint32_t m_process_id        = { }; ///< Process ID
        uint32_t m_directory_hash    = { }; ///< Hash of process directory
        uint32_t m_access_flags      = { }; ///< Process access flags
        uint32_t m_creation_time_low = { }; ///< Process creation time (low part)
        uint32_t m_parent_process_id = { }; ///< Parent process ID
        uint32_t m_additional_flags  = { }; ///< Additional process flags
    };

    /**
     * @brief Hash table entry structure - 20 bytes each
     */
    struct hash_entry_t {
        uint32_t m_hash_value      = { }; ///< +0: Hash value
        uint32_t m_string_pointer  = { }; ///< +4: Pointer to string data
        uint32_t m_string_length   = { }; ///< +8: String length
        uint32_t m_reference_count = { }; ///< +12: Reference count
        uint8_t  m_flags           = { }; ///< +16: Flags
        uint8_t  m_padding[ 3 ]    = { }; ///< +17-19: Padding
    };

    /**
     * @brief Hash table context structure
     */
    struct hash_table_context_t {
        uint32_t m_entry_count        = { }; ///< Number of entries
        uint32_t m_entries_buffer     = { }; ///< Buffer for hash entries
        uint8_t  m_gap8[ 4 ]          = { }; // +8
        char    *m_strings_buffer     = { }; ///< Buffer for string data
        uint32_t m_string_buffer_used = { }; ///< Used space in string buffer
    };

    /**
     * @brief Dynamic array for hash lookups
     */
    struct hash_lookup_array_t {
        void *m_data_buffer = { }; ///< Data buffer
        void *m_current_end = { }; ///< Current end pointer
        void *m_buffer_end  = { }; ///< Buffer end pointer
    };

    /**
     * @brief Process analysis context structure
     */
    struct process_analysis_context_t {
        char     m_gap0[ 8 ]            = { }; ///< Unknown/padding
        uint8_t  m_include_terminated   = { }; ///< Include terminated processes
        uint8_t  m_filter_by_uptime     = { }; ///< Filter by process uptime
        uint8_t  m_detailed_analysis    = { }; ///< Enable detailed analysis
        char     m_gap0B[ 1 ]           = { }; ///< Padding
        uint32_t m_uptime_threshold     = { }; ///< Uptime threshold (this + 12)
        uint32_t m_analysis_buffer_ptr  = { }; ///< Pointer to analysis buffer (this + 16)
        int      m_hash_table_context1  = { }; ///< Hash table context 1 (this + 20)
        char     m_gap18[ 12 ]          = { }; ///< Padding
        uint32_t m_current_buffer_size  = { }; ///< Current buffer usage (this + 36)
        int      m_hash_table_context2  = { }; ///< Hash table context 2 (this + 40)
        char     m_gap2C[ 12 ]          = { }; ///< Padding
        uint32_t m_additional_data_size = { }; ///< Additional data size (this + 56)
        uint32_t m_hash_lookup_array1   = { }; ///< Hash lookup array 1 (this + 60)
        char     m_gap40[ 8 ]           = { }; ///< Padding
        uint32_t m_hash_lookup_array2   = { }; ///< Hash lookup array 2 (this + 72)
        char     m_gap4C[ 8012 ]        = { }; ///< Large padding/data
        uint32_t m_time_reference       = { }; ///< Time reference (this + 8088)
    };

    /**
     * @brief Process information section magic signature
     */
    constexpr uint32_t PROCESS_INFO_SECTION_MAGIC = 0x907A6BB2;

    /**
     * @brief Error codes returned by process informer module
     */
    enum class informer_error_code_t : uint16_t {
        success                     = 0,   ///< Successfully read process information
        invalid_input_context       = 78,  ///< Input context validation failed
        library_load_failed         = 390, ///< Failed to load required library
        open_mapping_api_missing    = 400, ///< OpenFileMappingW API not found
        query_directory_api_missing = 410, ///< NtQueryDirectoryObject API not found
        section_access_failed       = 440, ///< Section access failed (not ERROR_FILE_NOT_FOUND)
        directory_enum_failed       = 466, ///< Directory enumeration failed
        section_mapping_failed      = 483  ///< MapViewOfFile failed
    };

    /**
     * @brief Process information section data structure
     *
     * This structure represents the layout of the shared memory section
     * that contains system process information. The section is typically
     * created by anti-cheat drivers or system components.
     */
    struct process_info_section_t {
        uint32_t m_magic_signature      = { }; ///< +0: Magic signature (0x907A6BB2)
        uint32_t m_section_size         = { }; ///< +4: Total section size
        uint32_t m_process_count        = { }; ///< +8: Number of processes
        uint32_t m_last_update_time     = { }; ///< +12: Last update timestamp
        uint32_t m_flags                = { }; ///< +16: Section flags
        uint32_t m_reserved             = { }; ///< +20: Reserved field
        uint8_t  m_process_data[ 4072 ] = { }; ///< +24: Process information data
        uint32_t m_checksum             = { }; ///< +4096: Data integrity checksum
    };

    /**
     * @brief CPU information entry structure (24 bytes each)
     */
    struct cpu_info_entry_t {
        uint32_t m_eax_value     = { }; ///< +0: EAX register value
        uint32_t m_ebx_value     = { }; ///< +4: EBX register value
        uint32_t m_ecx_value     = { }; ///< +8: ECX register value
        uint32_t m_edx_value     = { }; ///< +12: EDX register value
        uint32_t m_function_code = { }; ///< +16: CPUID function code used
        uint32_t m_sub_function  = { }; ///< +20: CPUID sub-function/leaf
    };

    /**
     * @brief CPUID analysis context structure
     */
    struct cpuid_analysis_context_t {
        char             m_gap0[ 28 ]         = { }; ///< Unknown/padding (offset 0-27)
        uint32_t         m_entry_count        = { }; ///< +28: Number of CPU info entries
        char             m_gap20[ 12 ]        = { }; ///< Padding (offset 32-43)
        cpu_info_entry_t m_cpu_entries[ 169 ] = { }; ///< +44: CPU info entries array (169 max)
        uint32_t         m_analysis_result    = { }; ///< +4100: Final analysis result
    };

    /**
     * @brief CPUID function descriptor for lookup table
     */
    struct cpuid_function_descriptor_t {
        uint32_t m_function_code                                      = { }; ///< CPUID function code to query
        bool( __cdecl *m_validator )( int context, int entry_offset ) = { }; ///< Validation function pointer
    };

    /**
     * @brief PnP device entry structure (8 bytes each)
     */
    struct pnp_device_entry_t {
        uint32_t m_type_and_class = { }; ///< +0: Type flags (bits 0-3) | Class code (bits 4-31)
        uint16_t m_vendor_id      = { }; ///< +4: Vendor ID (VID)
        uint16_t m_product_id     = { }; ///< +6: Product ID (PID)
    };

    /**
     * @brief PnP device scan results structure
     */
    struct pnp_scan_results_t {
        char               m_reserved[ 32 ] = { }; ///< +0: Reserved header space
        uint32_t           m_error_code     = { }; ///< +32: Error code from scan operation
        uint32_t           m_device_count   = { }; ///< +36: Number of unique devices found
        uint32_t           m_scan_flags     = { }; ///< +40: Scan operation flags
        pnp_device_entry_t m_devices[ 508 ] = { }; ///< +44: Device entries (max 508 devices)
    };

} // namespace vac::common
