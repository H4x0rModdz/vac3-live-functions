#include "process_analyzer.hpp"

#include "../../utils/vac_hash_utils.hpp"
#include "../../utils/vac_path_utils.hpp"
#include "../../utils/vac_string_utils.hpp"

#include <psapi.h>

namespace vac::modules::process_analyzer {
    char analyze_process_entry( common::process_analysis_context_t *analysis_context, const uint32_t process_id,
                                const uint32_t access_flags, const uint32_t parent_process_id, [[maybe_unused]] uint32_t handle_info,
                                const uint32_t additional_flags ) {
        uint64_t process_times;

        uint32_t final_access_flags;
        uint32_t last_error;
        uint32_t final_directory_hash;

        FILETIME creation_time;
        FILETIME exit_time;
        int      exit_time_parts[ 2 ];
        FILETIME user_time;
        FILETIME kernel_time;

        // Get analysis buffer from context (this + 16)
        void          *analysis_buffer      = reinterpret_cast< void * >( analysis_context->m_analysis_buffer_ptr );
        const uint32_t current_entry_offset = 28 * *reinterpret_cast< uint32_t * >( static_cast< char * >( analysis_buffer ) + 36 );
        HANDLE         process_handle       = OpenProcess( PROCESS_QUERY_INFORMATION, FALSE, process_id );

        // Fallback check
        if ( !g_system_info.supports_limited_query_info( ) && ( !process_handle || process_handle == INVALID_HANDLE_VALUE ) ) {
            process_handle = OpenProcess( PROCESS_QUERY_LIMITED_INFORMATION, FALSE, process_id );
        }

        process_times = 0;

        if ( !process_handle || process_handle == INVALID_HANDLE_VALUE ) {
            // Failed to open process
            last_error = GetLastError( );
            if ( last_error != ERROR_INVALID_PARAMETER || access_flags != PROCESS_QUERY_INFORMATION ) {
                final_directory_hash = 0;
                final_access_flags   = access_flags | 0x80000000;
                goto LOG_PROCESS_ENTRY;
            }
        } else {
            uint32_t       creation_time_high = 0;
            const uint32_t creation_time_low  = 0;
            uint32_t       process_name_hash  = 0;
            WCHAR          process_path_unicode[ 512 ];
            char           directory_path_ansi[ 264 ];
            char           process_path_ansi[ 264 ];

            // Successfully opened process
            ++*reinterpret_cast< uint32_t * >( static_cast< char * >( analysis_buffer ) + 24 );

            const uint32_t path_length = GetProcessImageFileNameW( process_handle, process_path_unicode, 512 );

            utils::normalize_process_path( process_path_unicode, path_length );

            const BOOL process_times_result = GetProcessTimes(
                process_handle, &creation_time, reinterpret_cast< LPFILETIME >( &exit_time_parts ), &kernel_time, &user_time );

            CloseHandle( process_handle );

            if ( !process_times_result ) {
                final_access_flags = access_flags;
                goto PROCESS_PATH_ANALYSIS;
            }

            utils::copy_memory_vac( reinterpret_cast< unsigned char * >( &process_times ), reinterpret_cast< intptr_t >( &creation_time ),
                                    4 );

            utils::copy_memory_vac( reinterpret_cast< unsigned char * >( &process_times ) + 4, reinterpret_cast< intptr_t >( &exit_time ),
                                    4 );

            if ( exit_time_parts[ 1 ] || exit_time_parts[ 0 ] ) {
                if ( !analysis_context->m_include_terminated )
                    return 1; // Skip terminated processes
                final_access_flags = access_flags | 0x20000000;
            } else {
                final_access_flags = access_flags;
            }

            const uint32_t process_uptime_seconds = utils::convert_filetime_to_seconds( process_times, process_times >> 32, 10000000, 0 );

            const bool skip_uptime_filter = ( analysis_context->m_filter_by_uptime == 0 );
            creation_time_high            = process_uptime_seconds;

            if ( !skip_uptime_filter ) {
                uint32_t uptime_check = analysis_context->m_time_reference;
                if ( uptime_check <= process_uptime_seconds )
                    goto PROCESS_PATH_ANALYSIS;
                uptime_check -= process_uptime_seconds;

                if ( uptime_check <= analysis_context->m_uptime_threshold )
                    goto PROCESS_PATH_ANALYSIS;
            }

        PROCESS_PATH_ANALYSIS:
            // Process path and directory extraction
            uint32_t directory_length = 0; // i = 0

            if ( ( path_length - 1 ) <= 0x1FE ) {
                LPCWSTR last_backslash_pos = utils::find_last_backslash( process_path_unicode );

                if ( last_backslash_pos > process_path_unicode ) {
                    WCHAR *path_end                                      = nullptr;
                    *( const_cast< WCHAR * >( last_backslash_pos ) - 1 ) = 0;
                }

                utils::convert_unicode_to_ansi( reinterpret_cast< intptr_t >( last_backslash_pos ),
                                                reinterpret_cast< intptr_t >( directory_path_ansi ) );

                directory_length = 0;
                while ( directory_path_ansi[ directory_length ] ) {
                    ++directory_length;
                }
            }

            utils::convert_unicode_to_ansi( reinterpret_cast< intptr_t >( process_path_unicode ),
                                            reinterpret_cast< intptr_t >( process_path_ansi ) );

            uint32_t path_ansi_length  = 0;
            uint32_t final_path_length = 0;

            // Calculate ANSI path length
            if ( process_path_ansi[ 0 ] ) {
                do {
                    ++path_ansi_length;
                } while ( process_path_ansi[ path_ansi_length ] );
                final_path_length = path_ansi_length;
            }

            // Check buffer space for detailed analysis
            if ( analysis_context->m_detailed_analysis ) {
                // Buffer space check: i + v17 + *(_DWORD *)(this + 36) + *(_DWORD *)(this + 56) + 2 >
                // 28 * (143 - *(_DWORD *)(*(_DWORD *)(this + 16) + 36))
                if ( directory_length + path_ansi_length + analysis_context->m_current_buffer_size
                         + analysis_context->m_additional_data_size + 2
                     > 28 * ( 143 - *reinterpret_cast< uint32_t * >( static_cast< char * >( analysis_buffer ) + 36 ) ) ) {
                    return 0; // Insufficient buffer space
                }
                path_ansi_length = final_path_length;
            }

            // Generate hashes and store string data
            if ( directory_length ) {
                process_name_hash
                    = utils::calculate_string_hash( reinterpret_cast< const unsigned char * >( process_path_ansi ), path_ansi_length );

                utils::store_string_data( reinterpret_cast< common::hash_table_context_t * >( &analysis_context->m_hash_table_context1 ),
                                          process_name_hash, reinterpret_cast< intptr_t >( process_path_ansi ), final_path_length );

                utils::add_hash_to_lookup( reinterpret_cast< common::hash_lookup_array_t * >( analysis_context->m_hash_lookup_array1 ),
                                           process_name_hash );

                const uint32_t directory_hash
                    = utils::calculate_string_hash( reinterpret_cast< const unsigned char * >( directory_path_ansi ), directory_length );

                utils::store_string_data( reinterpret_cast< common::hash_table_context_t * >( &analysis_context->m_hash_table_context2 ),
                                          directory_hash, reinterpret_cast< intptr_t >( directory_path_ansi ), directory_length );

                final_directory_hash = directory_hash;

                utils::add_hash_to_lookup( reinterpret_cast< common::hash_lookup_array_t * >( analysis_context->m_hash_lookup_array2 ),
                                           directory_hash );

                last_error = creation_time_low;
            } else {
                last_error           = creation_time_low;
                final_directory_hash = creation_time_low;
            }

        LOG_PROCESS_ENTRY:
            // Store process entry in analysis buffer
            const uint32_t entry_offset = current_entry_offset;

            // Fill process entry structure
            *reinterpret_cast< uint32_t * >( static_cast< char * >( analysis_buffer ) + entry_offset + 88 ) = 0;
            *reinterpret_cast< uint32_t * >( static_cast< char * >( analysis_buffer ) + entry_offset + 64 ) = process_name_hash;
            *reinterpret_cast< uint32_t * >( static_cast< char * >( analysis_buffer ) + entry_offset + 72 ) = process_id;
            *reinterpret_cast< uint32_t * >( static_cast< char * >( analysis_buffer ) + entry_offset + 68 ) = final_directory_hash;
            *reinterpret_cast< uint32_t * >( static_cast< char * >( analysis_buffer ) + entry_offset + 76 ) = final_access_flags;

            uint32_t final_creation_time = creation_time_high;
            if ( !process_times )
                final_creation_time = last_error;

            *reinterpret_cast< uint32_t * >( static_cast< char * >( analysis_buffer ) + entry_offset + 88 ) = final_creation_time;
            *reinterpret_cast< uint32_t * >( static_cast< char * >( analysis_buffer ) + entry_offset + 80 ) = parent_process_id;
            *reinterpret_cast< uint32_t * >( static_cast< char * >( analysis_buffer ) + entry_offset + 84 ) = additional_flags;

            ++*reinterpret_cast< uint32_t * >( static_cast< char * >( analysis_buffer ) + 36 );
        }

        return 1; // Success
    }
} // namespace vac::modules::process_analyzer