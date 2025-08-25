#include "system_handle_query.hpp"
#include <cstring>
#include <memory>
#include <windows.h>

namespace vac::modules::handle_scanner {
    int __fastcall query_system_handle_information( uint32_t *process_id_table,     // a1 - hash table for process lookups
                                                    int       max_process_count,    // a2 - max processes to track
                                                    [[maybe_unused]] int       unused_param,         // a3 - unused
                                                    uint32_t *unique_process_count, // a4 - output: unique process count
                                                    uint32_t *total_handle_count,   // a5 - output: total handle count
                                                    uint64_t *handle_info_buffer )  // a6 - buffer for handle info storage
    {
        // Obfuscated API name storage
        char obfuscated_api_name[ 32 ];
        char v35[ 8 ];

        char obfuscated_char = 16;

        // Build obfuscated "NtQuerySystemInformation" string
        constexpr uint32_t v31 = 992677674;
        constexpr uint32_t v32 = 655173420;
        constexpr uint32_t v33 = 859515437;
        constexpr uint32_t v34 = 825765911;
        strcpy( v35, ",3?*710" );

        // Build obfuscated string in memory
        *reinterpret_cast< uint32_t * >( &obfuscated_api_name[ 0 ] )  = obfuscated_char;
        *reinterpret_cast< uint32_t * >( &obfuscated_api_name[ 1 ] )  = v31;
        *reinterpret_cast< uint32_t * >( &obfuscated_api_name[ 5 ] )  = v32;
        *reinterpret_cast< uint32_t * >( &obfuscated_api_name[ 9 ] )  = v33;
        *reinterpret_cast< uint32_t * >( &obfuscated_api_name[ 13 ] ) = v34;
        strcpy( &obfuscated_api_name[ 17 ], v35 );

        // Deobfuscate API name using XOR with 0x5E
        char *deobfuscation_ptr = obfuscated_api_name;
        do {
            *deobfuscation_ptr++ = obfuscated_char ^ 0x5E;
            obfuscated_char      = *deobfuscation_ptr;
        } while ( *deobfuscation_ptr );

        // Get NtQuerySystemInformation function pointer
        const HMODULE ntdll = GetModuleHandleA( "ntdll.dll" ); // dword_10007C6C
        NTSTATUS( __stdcall * nt_query_system_information )( int, int, int, uint32_t )
            = reinterpret_cast< NTSTATUS( __stdcall * )( int, int, int, uint32_t ) >( GetProcAddress( ntdll, obfuscated_api_name ) );

        if ( nt_query_system_information ) {
            int       final_result;
            int       last_error_code      = 0;
            uint32_t *system_handle_buffer = nullptr;
            int       buffer_size          = 0;

            // Progressive buffer allocation loop
            while ( true ) {
                buffer_size += 0x100000;

                // Free previous buffer if exists
                if ( system_handle_buffer )
                    VirtualFree( system_handle_buffer, 0, MEM_RELEASE );

                // Allocate new buffer using VirtualAlloc
                system_handle_buffer
                    = static_cast< uint32_t * >( VirtualAlloc( nullptr, buffer_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE ) );

                if ( !system_handle_buffer )
                    break;

                // Query system handle information
                const int query_result = nt_query_system_information( 16, // SystemHandleInformation
                                                                      reinterpret_cast< int >( system_handle_buffer ), buffer_size, 0 );

                if ( query_result != 0xC0000004 ) { // if (result != -1073741820 (STATUS_INFO_LENGTH_MISMATCH))
                    if ( query_result ) {
                        // Query failed with different error
                        last_error_code = query_result;
                    } else {
                        // Success - process handle information
                        const int table_lookup_index = *system_handle_buffer;

                        *total_handle_count   = table_lookup_index;
                        *unique_process_count = 0;

                        if ( table_lookup_index > 0 ) {
                            int processed_handle_count = 0;
                            int hash_table_index       = 0;
                            int handle_index           = 0;

                            // Start after count DWORD, each handle entry is 16 bytes
                            unsigned char *current_handle_ptr = reinterpret_cast< unsigned char * >( system_handle_buffer + 2 );
                            unsigned char *handle_data_ptr    = current_handle_ptr;

                            do {
                                // Extract process ID from handle entry (4 bytes before current position)
                                const uint32_t current_process_id = *( reinterpret_cast< uint32_t * >( current_handle_ptr ) - 1 );

                                // Search for process ID in hash table
                                for ( int process_search_loop = 0; process_search_loop < max_process_count; ++process_search_loop ) {
                                    if ( process_id_table[ hash_table_index ] == current_process_id )
                                        goto PROCESS_FOUND_IN_TABLE;

                                    if ( ++hash_table_index >= max_process_count )
                                        hash_table_index %= max_process_count;
                                }

                                // New process ID found
                                ++( *unique_process_count );
                                if ( max_process_count < 500 ) {
                                    process_id_table[ max_process_count ] = current_process_id;
                                    hash_table_index                      = max_process_count++;
                                }

                            PROCESS_FOUND_IN_TABLE:
                                // Process handle information if process ID matches
                                if ( process_id_table[ hash_table_index ] == current_process_id ) {
                                    int                 access_mask_calculation  = 0;
                                    int                 handle_flags_calculation = 0;
                                    const unsigned char object_type_index        = *handle_data_ptr;

                                    // Decode object type index
                                    if ( object_type_index < 0x37 ) {
                                        if ( object_type_index >= 0x20 )
                                            handle_flags_calculation = 1 << object_type_index;
                                        access_mask_calculation = handle_flags_calculation ^ ( 1 << object_type_index );
                                        if ( object_type_index >= 0x40 )
                                            handle_flags_calculation ^= 1 << object_type_index;
                                    }

                                    // Get existing handle information for this process
                                    const uint32_t existing_handle_low
                                        = *( reinterpret_cast< uint32_t * >( handle_info_buffer ) + 8 * hash_table_index );
                                    uint32_t existing_handle_high
                                        = *( reinterpret_cast< uint32_t * >( handle_info_buffer ) + 8 * hash_table_index + 4 );

                                    if ( existing_handle_high < 0xFF000000 ) {
                                        existing_handle_high
                                            = static_cast< uint32_t >(
                                                  ( ( static_cast< uint64_t >( existing_handle_high ) << 32 ) | existing_handle_low )
                                                  + 0x100000000000000ULL )
                                           >> 32;
                                    }

                                    const int combined_handle_flags = handle_flags_calculation | existing_handle_high;
                                    handle_index                    = processed_handle_count;

                                    // Update handle information
                                    *( reinterpret_cast< uint32_t * >( handle_info_buffer ) + 8 * hash_table_index )
                                        = access_mask_calculation | existing_handle_low;
                                    *( reinterpret_cast< uint32_t * >( handle_info_buffer ) + 8 * hash_table_index + 4 )
                                        = combined_handle_flags;
                                }

                                ++handle_index;
                                current_handle_ptr      = handle_data_ptr + 16;
                                processed_handle_count  = handle_index;
                                handle_data_ptr        += 16;

                            } while ( handle_index < *system_handle_buffer );
                        }

                        final_result = 0;
                    }

                    // Cleanup and return
                    if ( system_handle_buffer ) {
                        VirtualFree( system_handle_buffer, 0, MEM_RELEASE );
                        return last_error_code;
                    }
                    return final_result;
                }
                // Continue loop with larger buffer if STATUS_INFO_LENGTH_MISMATCH
            }
        }

        // Return GetLastError() if we reach here
        return GetLastError( );
    }

} // namespace vac::modules::handle_scanner