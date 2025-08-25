#include "pnp_device_scanner.hpp"

#include "../../common/types.hpp"
#include "../../utils/vac_string_utils.hpp"

#include <algorithm>
#include <cstring>
#include <setupapi.h>
#include <windows.h>

namespace vac::common {
    struct pnp_device_entry_t;
    struct pnp_scan_results_t;
} // namespace vac::common

namespace vac::modules::pnp_device_scanner {
    // Obfuscated search strings
    constexpr char g_obfuscated_ven_string[ 5 ]       = "h{pa";               // XOR 0x3E -> "VEN_"
    constexpr char g_obfuscated_dev_string[ 5 ]       = "z{ha";               // XOR 0x3E -> "DEV_"
    constexpr char g_obfuscated_vid_string[ 5 ]       = "hwza";               // XOR 0x3E -> "VID_"
    constexpr char g_obfuscated_pid_string[ 5 ]       = "nwza";               // XOR 0x3E -> "PID_"
    constexpr char g_obfuscated_cc_string[ 3 ]        = { 0x61, 0x61, 0x61 }; // XOR 0x3E -> "CC_"
    constexpr char g_obfuscated_devclass_string[ 10 ] = "z[H}R_MMa";          // XOR 0x3E -> "DevClass_"
    constexpr char g_obfuscated_class_string[ 8 ]     = "b}R_MMa";            // XOR 0x3E -> "\\Class_"
    constexpr char g_obfuscated_subclass_string[ 10 ] = "mK\\}R_MMa";         // XOR 0x3E -> "SubClass_"
    constexpr char g_obfuscated_prot_string[ 6 ]      = "nLQJa";              // XOR 0x3E -> "Prot_"

    // Hardware device classification lookup table - exact VAC data at dword_10001080
    constexpr uint32_t g_hardware_device_lookup_table[] = {
        // Table header: device count (10) followed by padding
        0x0A, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,

        // Device entries: [device_id, classification_code] pairs
        // Graphics devices (NVIDIA, AMD, Intel)
        0x7918D4, 0x1F, 0x44FB326, 0x1F, 0x45E028E, 0x1F, 0x45E028F, 0x1F, 0x45E0291, 0x1F, 0x45E02A0, 0x1F, 0x45E02A1, 0x1F, 0x45E02D1,
        0x20, 0x45E02DD, 0x20,

        // Network devices
        0x1A340836, 0x21, 0xF0D006E, 0x21, 0x8100001, 0x21,

        // Storage devices
        0x1BAD0002, 0x1F, 0x1BADF016, 0x1F, 0x24C65000, 0x1F,

        // Virtualization hardware (flagged with higher classification)
        0x15AD0405, 0x22, 0x1234111, 0x22, 0x80EE0021, 0x23,

        // Terminator
        0, 0
    };

    int __fastcall parse_hex_string( const int hex_string, const unsigned int length, uint32_t *result ) {
        int current_value = 0;

        if ( length ) {
            unsigned char temp_index = 0;
            unsigned char hex_digit;

            int char_index = 0;
            while ( true ) {
                const char current_char = *reinterpret_cast< char * >( char_index + hex_string );
                if ( !current_char ) {
                    return 2; // Null character encountered
                }

                // Convert to lowercase
                char processed_char = current_char + 32;
                if ( static_cast< unsigned int >( current_char - 65 ) > 0x19 ) {
                    processed_char = *reinterpret_cast< char * >( char_index + hex_string );
                }

                // Parse hex digit
                if ( static_cast< unsigned char >( processed_char - 48 ) > 9u ) {
                    if ( static_cast< unsigned char >( processed_char - 97 ) > 5u ) {
                        return 3; // Invalid hex character
                    }
                    hex_digit = processed_char - 87; // a-f -> 10-15
                } else {
                    hex_digit = processed_char - 48; // 0-9 -> 0-9
                }

                current_value = ( hex_digit << ( 4 * ( length - char_index ) - 4 ) ) + current_value;
                char_index    = ++temp_index;

                if ( temp_index >= length ) {
                    goto PARSE_COMPLETE;
                }
            }
        } else {
        PARSE_COMPLETE:
            *result = current_value;
            return 0; // Success
        }
    }

    int __cdecl enumerate_pnp_devices( [[maybe_unused]] void *context_param, char *results_buffer, unsigned int *buffer_size ) {
        unsigned int *buffer_size_ptr = buffer_size;
        DWORD         last_error;
        char         *device_buffer;
        int           required_size;
        char         *hw_id_start;
        unsigned int  vendor_id_result;
        unsigned int  product_id_result;
        unsigned int  class_code_result;
        unsigned int  device_type_flag;

        SP_DEVINFO_DATA device_info_data;
        unsigned int    temp_vendor_id;
        unsigned int    temp_class_code;

        char ven_string[ 5 ];       // "VEN_"
        char dev_string[ 5 ];       // "DEV_"
        char vid_string[ 5 ];       // "VID_"
        char pid_string[ 5 ];       // "PID_"
        char cc_string[ 4 ];        // "CC_"
        char devclass_string[ 10 ]; // "DevClass_"
        char class_string[ 8 ];     // "\\Class_"
        char subclass_string[ 10 ]; // "SubClass_"
        char prot_string[ 6 ];      // "Prot_"

        utils::zero_memory_vac( results_buffer, 0, 0x20u );
        common::pnp_scan_results_t *scan_results = reinterpret_cast< common::pnp_scan_results_t * >( results_buffer );
        *buffer_size_ptr                         = 32;
        scan_results->m_error_code               = static_cast< uint32_t >( -1811958236 );

        // Get device information set for all present devices
        const int device_info_handle
            = reinterpret_cast< int >( SetupDiGetClassDevsA( nullptr, nullptr, nullptr, DIGCF_PRESENT | DIGCF_ALLCLASSES ) );
        if ( device_info_handle == -1 ) {
            last_error = GetLastError( );
            goto CLEANUP_AND_RETURN;
        }

        // Allocate device enumeration buffer
        device_buffer = reinterpret_cast< char * >( HeapAlloc( GetProcessHeap( ), 0, 2048 ) );
        if ( !device_buffer ) {
            last_error = 14; // ERROR_OUTOFMEMORY
            goto CLEANUP_DEVICE_INFO;
        }

        utils::zero_memory_vac( device_buffer, 0, 0x800u );
        device_info_data.cbSize        = sizeof( SP_DEVINFO_DATA );
        unsigned int device_enum_index = 0;

        // Deobfuscate search strings
        deobfuscate_string( g_obfuscated_ven_string, ven_string, 4 );
        deobfuscate_string( g_obfuscated_dev_string, dev_string, 4 );
        deobfuscate_string( g_obfuscated_vid_string, vid_string, 4 );
        deobfuscate_string( g_obfuscated_pid_string, pid_string, 4 );
        deobfuscate_string( g_obfuscated_cc_string, cc_string, 3 );
        deobfuscate_string( g_obfuscated_devclass_string, devclass_string, 9 );
        deobfuscate_string( g_obfuscated_class_string, class_string, 7 );
        deobfuscate_string( g_obfuscated_subclass_string, subclass_string, 9 );
        deobfuscate_string( g_obfuscated_prot_string, prot_string, 5 );

        // Enumerate all devices
        while ( true ) {
            if ( !SetupDiEnumDeviceInfo( reinterpret_cast< HDEVINFO >( device_info_handle ), device_enum_index, &device_info_data ) ) {
                last_error = 0; // Success - no more devices
                goto CLEANUP_BUFFER;
            }

            *device_buffer = 0;

            // Get device description
            if ( !SetupDiGetDeviceRegistryPropertyA( reinterpret_cast< HDEVINFO >( device_info_handle ), &device_info_data,
                                                     SPDRP_DEVICEDESC, nullptr, reinterpret_cast< PBYTE >( device_buffer ), 1024,
                                                     reinterpret_cast< PDWORD >( &required_size ) ) ) {
                const DWORD get_error = GetLastError( );
                last_error      = get_error;
                if ( get_error != 13 && get_error != 122 ) { // Not access denied or insufficient buffer
                    if ( get_error != static_cast< DWORD >( -536870389 ) ) {
                        goto CLEANUP_BUFFER;
                    }
                    scan_results->m_scan_flags |= 1u; // Mark access error
                }
            }

            if ( !*device_buffer ) {
                goto NEXT_DEVICE;
            }

            // Append device class string to description
            const int device_desc_length = strlen( device_buffer );
            int max_append_length  = strlen( ( char * ) g_hardware_device_lookup_table );
            max_append_length      = std::min( max_append_length, 0xFFFF );

            memcpy( device_buffer + device_desc_length, g_hardware_device_lookup_table, max_append_length );
            device_buffer[ max_append_length + device_desc_length ] = 0;

            // Get hardware IDs
            const int current_buffer_length = strlen( device_buffer );
            hw_id_start               = &device_buffer[ current_buffer_length ];

            if ( !SetupDiGetDeviceRegistryPropertyA( reinterpret_cast< HDEVINFO >( device_info_handle ), &device_info_data,
                                                     SPDRP_HARDWAREID, nullptr, reinterpret_cast< PBYTE >( hw_id_start ),
                                                     1024 - current_buffer_length, reinterpret_cast< PDWORD >( &required_size ) ) ) {
                const DWORD hw_error = GetLastError( );
                last_error     = hw_error;
                if ( hw_error != 13 && hw_error != 122 ) {
                    if ( hw_error != static_cast< DWORD >( -536870389 ) ) {
                        goto CLEANUP_BUFFER;
                    }
                    scan_results->m_scan_flags |= 1u;
                }
            }

            // Handle multi-string hardware IDs (replace null separators with newlines)
            if ( required_size == 7 ) {
                char *hw_id_ptr = &hw_id_start[ strlen( hw_id_start ) ];
                while ( true ) {
                    *hw_id_ptr = 10; // newline
                    if ( !hw_id_ptr[ 1 ] ) {
                        break;
                    }
                    hw_id_ptr = &hw_id_ptr[ strlen( hw_id_ptr ) ];
                }
            }

            // Parse hardware IDs for VEN/DEV (primary method)
            vendor_id_result  = 0;
            product_id_result = 0;
            class_code_result = 0;

            char *string_search_pos = strstr( device_buffer, ven_string );
            char *dev_search_pos    = strstr( device_buffer, dev_string );
            char *cc_search_pos     = strstr( device_buffer, cc_string );

            if ( cc_search_pos ) {
                while ( parse_hex_string( reinterpret_cast< int >( cc_search_pos + 3 ), 6u, &class_code_result ) ) {
                    cc_search_pos = strstr( cc_search_pos + 3, cc_string );
                    if ( !cc_search_pos ) {
                        break;
                    }
                }
                if ( cc_search_pos ) {
                    class_code_result = class_code_result >> 8; // Extract class code
                }
            }

            if ( !string_search_pos || !dev_search_pos
                 || parse_hex_string( reinterpret_cast< int >( string_search_pos + 4 ), 4u, &vendor_id_result )
                 || parse_hex_string( reinterpret_cast< int >( dev_search_pos + 4 ), 4u, &product_id_result ) ) {
                // Fallback method: try VID/PID and various class code formats
                char *vid_search_pos      = strstr( device_buffer, vid_string );
                char *pid_search_pos      = strstr( device_buffer, pid_string );
                char *devclass_search_pos = strstr( device_buffer, devclass_string );
                char *class_search_pos    = strstr( device_buffer, class_string );
                char *subclass_search_pos = strstr( device_buffer, subclass_string );
                char *prot_search_pos     = strstr( device_buffer, prot_string );

                if ( !vid_search_pos || !pid_search_pos ) {
                    goto NEXT_DEVICE;
                }

                product_id_result            = 0;
                vendor_id_result             = 0;
                temp_class_code              = 0;
                temp_vendor_id               = 0;
                unsigned int temp_product_id = 0;

                if ( parse_hex_string( reinterpret_cast< int >( vid_search_pos + 4 ), 4u, &vendor_id_result )
                     || parse_hex_string( reinterpret_cast< int >( pid_search_pos + 4 ), 4u, &product_id_result ) ) {
                    goto NEXT_DEVICE;
                }

                // Parse various class code formats
                if ( devclass_search_pos ) {
                    parse_hex_string( reinterpret_cast< int >( devclass_search_pos + 9 ), 2u, &class_code_result );
                }
                if ( subclass_search_pos ) {
                    parse_hex_string( reinterpret_cast< int >( subclass_search_pos + 9 ), 2u, &temp_vendor_id );
                }
                if ( prot_search_pos ) {
                    parse_hex_string( reinterpret_cast< int >( prot_search_pos + 5 ), 2u, &temp_class_code );
                }

                class_code_result
                    = static_cast< unsigned char >( temp_vendor_id )
                    | ( ( ( static_cast< unsigned char >( class_code_result ) | ( static_cast< unsigned char >( temp_class_code ) << 8 ) )
                          << 8 ) );
                device_type_flag = 2; // Fallback method
            } else {
                device_type_flag = 1; // Primary method
            }

            // Check for duplicate devices
            const unsigned int current_device_count  = scan_results->m_device_count;
            unsigned int existing_device_index = 0;
            if ( current_device_count ) {
                const common::pnp_device_entry_t *existing_device = scan_results->m_devices;
                do {
                    if ( existing_device->m_vendor_id == vendor_id_result && existing_device->m_product_id == product_id_result
                         && static_cast< unsigned short >( class_code_result )
                                == static_cast< unsigned short >( existing_device->m_type_and_class >> 8 ) ) {
                        break; // Duplicate found
                    }
                    ++existing_device_index;
                    ++existing_device;
                } while ( existing_device_index < current_device_count );
            }

            if ( existing_device_index != current_device_count ) {
                goto NEXT_DEVICE; // Skip duplicate
            }

            // Add new device if space available
            if ( current_device_count < 508 ) { // Max devices = (4232-32)/8 = 525, but VAC uses 508
                common::pnp_device_entry_t *new_device = &scan_results->m_devices[ current_device_count ];

                new_device->m_type_and_class = device_type_flag | ( class_code_result << 8 );
                new_device->m_vendor_id      = static_cast< uint16_t >( vendor_id_result );
                new_device->m_product_id     = static_cast< uint16_t >( product_id_result );

                ++scan_results->m_device_count;
                goto NEXT_DEVICE;
            }

            last_error = 111; // ERROR_BUFFER_OVERFLOW
            break;

        NEXT_DEVICE:
            ++device_enum_index;
        }

    CLEANUP_BUFFER:
        HeapFree( GetProcessHeap( ), 0, device_buffer );

    CLEANUP_DEVICE_INFO:
        SetupDiDestroyDeviceInfoList( reinterpret_cast< HDEVINFO >( device_info_handle ) );

    CLEANUP_AND_RETURN:
        // Store final results
        scan_results->m_error_code = last_error;
        *buffer_size_ptr           = ( 8 * scan_results->m_device_count + 39 ) & 0xFFFFFFF8;
        return 0;
    }

} // namespace vac::modules::pnp_device_scanner