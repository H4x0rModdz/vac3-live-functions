#include "process_informer.hpp"
#include "../../utils/vac_string_utils.hpp"
#include <winternl.h>

namespace vac::modules::process_informer {
    int __cdecl read_process_information_section( unsigned __int8 *input_data, uint32_t *output_buffer, uint32_t *buffer_size ) {
        uint32_t error_code;

        // Clear output buffer
        utils::zero_memory_vac( reinterpret_cast< char * >( output_buffer ), 0, 4096 );
        *buffer_size = 4096;

        // Set magic signature
        output_buffer[ 4 ] = common::PROCESS_INFO_SECTION_MAGIC;

        // Obfuscated strings - XOR with 0x13 to get real names
        char obfuscated_kernel32[] = "xva}v"; // "kernel32" after XOR 0x13

        // Deobfuscate library name
        for ( char *p = obfuscated_kernel32; *p; ++p ) {
            *p ^= 0x13;
        }

        // Load kernel32.dll
        const HMODULE kernel32_handle = GetModuleHandleA( obfuscated_kernel32 );
        if ( !kernel32_handle ) {
            error_code = GetLastError( );
            goto cleanup;
        }

        // Build section GUID from input data
        WCHAR section_guid[ 48 ];
        wsprintfW( section_guid, L"{%02xDEDF05-86E9-%02x17-9E36-1D94%02x334DFA-A3%02x4421}", input_data[ 96 ], input_data[ 99 ],
                   input_data[ 98 ], input_data[ 97 ] );

        // Try to open the shared memory section
        HANDLE section_handle = OpenFileMappingW( FILE_MAP_READ, FALSE, section_guid );

        if ( !section_handle ) {
            const DWORD last_error = GetLastError( );

            if ( last_error != ERROR_FILE_NOT_FOUND ) {
                output_buffer[ 12 ] = static_cast< uint32_t >( common::informer_error_code_t::section_access_failed );
                error_code          = last_error;
                goto cleanup;
            }

            // Fallback: Try directory object enumeration
            section_handle = query_directory_object_for_section( section_guid );
            if ( !section_handle ) {
                output_buffer[ 12 ] = static_cast< uint32_t >( common::informer_error_code_t::directory_enum_failed );
                error_code          = static_cast< uint32_t >( common::informer_error_code_t::directory_enum_failed );
                goto cleanup;
            }
        }

        // Map the section into memory
        LPVOID mapped_section = MapViewOfFile( section_handle, FILE_MAP_READ, 0, 0, 0 );

        if ( mapped_section ) {
            // Copy process information data (4072 bytes starting at offset 0x18)
            utils::copy_memory_vac( reinterpret_cast< unsigned char * >( output_buffer + 6 ),
                                    reinterpret_cast< intptr_t >( mapped_section ) + 0x18, 4072 );

            // Copy metadata from input
            output_buffer[ 9 ]  = reinterpret_cast< uint32_t * >( input_data )[ 24 ];
            output_buffer[ 10 ] = reinterpret_cast< uint32_t * >( input_data )[ 24 ];

            UnmapViewOfFile( mapped_section );
            error_code = 0; // Success
        } else {
            error_code          = GetLastError( );
            output_buffer[ 12 ] = static_cast< uint32_t >( common::informer_error_code_t::section_mapping_failed );
        }

        CloseHandle( section_handle );

    cleanup:
        output_buffer[ 5 ] = error_code;
        return 0;
    }

    HANDLE __fastcall query_directory_object_for_section( const WCHAR *section_name ) {
        typedef NTSTATUS( NTAPI * NtOpenDirectoryObject_t )( PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES );
        typedef NTSTATUS( NTAPI * NtQueryDirectoryObject_t )( HANDLE, PVOID, ULONG, BOOLEAN, BOOLEAN, PULONG, PULONG );

        const HMODULE                 ntdll = GetModuleHandleA( "ntdll.dll" );
        const NtOpenDirectoryObject_t NtOpenDirectory
            = reinterpret_cast< NtOpenDirectoryObject_t >( GetProcAddress( ntdll, "NtOpenDirectoryObject" ) );
        const NtQueryDirectoryObject_t NtQueryDirectory
            = reinterpret_cast< NtQueryDirectoryObject_t >( GetProcAddress( ntdll, "NtQueryDirectoryObject" ) );

        if ( !NtOpenDirectory || !NtQueryDirectory ) {
            return nullptr;
        }

        HANDLE            directory_handle = nullptr;
        OBJECT_ATTRIBUTES obj_attrs        = { };
        obj_attrs.Length                   = sizeof( OBJECT_ATTRIBUTES );
        obj_attrs.Attributes               = OBJ_CASE_INSENSITIVE;

        NTSTATUS status = NtOpenDirectory( &directory_handle, 0x0003, &obj_attrs ); // DIRECTORY_QUERY | DIRECTORY_TRAVERSE
        if ( !NT_SUCCESS( status ) ) {
            return nullptr;
        }

        // Allocate buffer for directory enumeration
        ULONG  buffer_size = 1024;
        PVOID  buffer      = HeapAlloc( GetProcessHeap( ), 0, buffer_size );
        ULONG  context     = 0;
        ULONG  return_length;
        HANDLE found_section = nullptr;

        while ( buffer ) {
            status = NtQueryDirectory( directory_handle, buffer, buffer_size, TRUE, FALSE, &context, &return_length );

            if ( status == 0xC0000023 ) {
                HeapFree( GetProcessHeap( ), 0, buffer );
                buffer_size += 1024;
                buffer       = HeapAlloc( GetProcessHeap( ), 0, buffer_size );
                continue;
            }

            if ( !NT_SUCCESS( status ) ) {
                break;
            }

            typedef struct _OBJECT_DIRECTORY_INFORMATION {
                UNICODE_STRING Name;
                UNICODE_STRING TypeName;
            } *POBJECT_DIRECTORY_INFORMATION;

            // Parse directory entry and check if it matches our section name
            const POBJECT_DIRECTORY_INFORMATION dir_info = static_cast< POBJECT_DIRECTORY_INFORMATION >( buffer );

            if ( dir_info->Name.Buffer && lstrcmpiW( dir_info->Name.Buffer, section_name ) == 0 ) {
                // Found the section - try to open it
                found_section = OpenFileMappingW( FILE_MAP_READ, FALSE, section_name );
                break;
            }
        }

        if ( buffer ) {
            HeapFree( GetProcessHeap( ), 0, buffer );
        }

        if ( directory_handle ) {
            CloseHandle( directory_handle );
        }

        return found_section;
    }
} // namespace vac::modules::process_informer