#pragma once
#include "../../common/types.hpp"
#include "../../utils/vac_string_utils.hpp"

namespace vac::modules::process_informer {
    /**
     * @brief Read process information from shared memory section
     *
     * This function attempts to access a shared memory section containing process information.
     * The section GUID is constructed from input data bytes at specific offsets.
     *
     * GUID Format: "{%02xDEDF05-86E9-%02x17-9E36-1D94%02x334DFA-A3%02x4421}"
     * Where bytes come from: input_data[96], input_data[99], input_data[98], input_data[97]
     *
     * Error 0x1D2 (466) indicates the section doesn't exist - likely disabled on modern Windows.
     *
     * @param input_data Input context data containing GUID bytes at offsets 96-99
     * @param output_buffer Output buffer (4096 bytes)
     * @param buffer_size Buffer size pointer (set to 4096)
     * @return Always 0, error code stored in output_buffer[5]
     */
    int __cdecl read_process_information_section( unsigned __int8 *input_data, uint32_t *output_buffer, uint32_t *buffer_size );

    /**
     * @brief Query directory object recursively
     *
     * This function performs recursive directory object enumeration to locate
     * the process information section when direct access fails. Uses progressive
     * buffer allocation to handle varying directory sizes.
     *
     * Implementation details:
     * - Opens directory object with DIRECTORY_QUERY | DIRECTORY_TRAVERSE access
     * - Uses NtQueryDirectoryObject with single entry enumeration
     * - Progressively expands buffer size on STATUS_BUFFER_TOO_SMALL
     * - Performs case-insensitive string comparison for object names
     * - Returns handle to located section object
     *
     * @return Handle to section object, or NULL if not found
     */
    HANDLE __fastcall query_directory_object_for_section( const WCHAR *section_name );
} // namespace vac::modules::process_informer