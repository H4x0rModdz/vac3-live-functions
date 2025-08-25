#include "vac_string_utils.hpp"

namespace vac::utils {
    unsigned char * copy_memory_vac( unsigned char *dest, const intptr_t source, const int length ) {
        int            remaining = length;
        unsigned char *result    = dest;
        if ( length ) {
            unsigned char *current = dest;
            do {
                *current = current[ source - reinterpret_cast< intptr_t >( dest ) ];
                ++current;
                --remaining;
            } while ( remaining );
        }
        return result;
    }

    char *zero_memory_vac( char *buffer, const char fill_value, const uint32_t size ) {
        if ( size ) {
            // Fill in 4-byte chunks
            const uint32_t fill_pattern = 16843009 * static_cast< unsigned char >( fill_value ); // 0x01010101 * fill_value
            memset( buffer, fill_pattern, size >> 2 );
            // Fill remaining bytes
            memset( &buffer[ 4 * ( size >> 2 ) ], fill_value, size & 3 );
        }
        return buffer;
    }

    unsigned char *copy_wide_string_vac( unsigned char *dest, const WCHAR *source ) {
        copy_memory_vac( dest, reinterpret_cast< intptr_t >( source ), 1024 );
        const uint32_t length = lstrlenW( source );
        if ( length < 0x200 ) {
            zero_memory_vac( reinterpret_cast< char * >( &dest[ 2 * length ] ), 0, 2 * ( 512 - length ) );
        }
        return dest;
    }
} // namespace vac::utils