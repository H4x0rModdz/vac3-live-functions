#include "vac_path_utils.hpp"
#include "vac_string_utils.hpp"

namespace vac::utils {
    int __fastcall compare_string_case_insensitive( const PCNZWCH string1, const PCNZWCH string2, const int count ) {
        return CompareStringW( 0x800u, NORM_IGNORECASE, string1, count, string2, count ) - 2;
    }

    LPCWSTR find_last_backslash( const LPCWSTR path ) {
        const WCHAR *current;
        int          length = lstrlenW( path ) - 1;
        if ( length <= 0 )
            return path;

        for ( current = &path[ length ]; *current != L'\\'; --current ) {
            if ( --length <= 0 )
                return path;
        }
        return current + 1;
    }

    int __fastcall convert_unicode_to_ansi( const intptr_t unicode_string, const intptr_t ansi_buffer ) {
        const int result = WideCharToMultiByte( CP_UTF8, // Code page
                                          0,       // Flags
                                          reinterpret_cast< LPCWCH >( unicode_string ),
                                          -1, // Null-terminated
                                          reinterpret_cast< LPSTR >( ansi_buffer ),
                                          260,     // Buffer size
                                          nullptr, // Default char
                                          nullptr  // Used default char
        );

        if ( !result ) {
            *reinterpret_cast< char * >( ansi_buffer + 259 ) = 0; // Ensure null termination
        }
        return result;
    }

    char __stdcall normalize_process_path( const PCNZWCH process_path, [[maybe_unused]] int unused_param ) {
        WCHAR    drive_letters[ 520 ];
        WCHAR    drive_root[ 4 ];
        WCHAR    full_path[ 260 ];
        WCHAR    normalized_path[ 260 ];
        uint32_t device_length;

        drive_letters[ 0 ] = 0;

        // Get logical drive strings
        if ( !GetLogicalDriveStringsW( 250, drive_letters ) )
            return 0;

        const WCHAR *current_drive = drive_letters;
        wcscpy_s( drive_root, 4, L"C:" );

        WCHAR current_letter = drive_letters[ 0 ];
        while ( current_letter ) {
            drive_root[ 0 ] = current_letter;

            // Query DOS device for this drive
            if ( QueryDosDeviceW( drive_root, full_path, 260 ) ) {
                device_length = lstrlenW( full_path );

                if ( device_length < 0x104 && !compare_string_case_insensitive( process_path, full_path, device_length ) ) {
                    break; // Found matching device
                }
            }

            // Move to next drive letter
            while ( *current_drive++ )
                ;
            current_letter = *current_drive;
            if ( !current_letter )
                return 0;
        }

        // Build normalized path
        normalized_path[ 0 ] = 0;
        lstrcatW( normalized_path, drive_root );
        lstrcatW( normalized_path, &process_path[ device_length ] );

        // Copy back to original buffer
        copy_wide_string_vac( ( unsigned char * ) process_path, normalized_path );
        return 1;
    }
} // namespace vac::utils