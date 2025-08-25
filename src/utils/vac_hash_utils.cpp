#include "vac_hash_utils.hpp"
#include "../common/types.hpp"
#include "vac_string_utils.hpp"

namespace vac::utils {
    uint32_t __fastcall calculate_string_hash( const unsigned char *string, const int length ) {
        uint32_t hash = 1171724434; // Starting hash value
        for ( int i = 0; i < length; ++i ) {
            hash = ( string[ i ] | 0x20 ) + 33 * hash; // Lowercase + hash
        }
        return hash;
    }

    int store_string_data( common::hash_table_context_t *context, const uint32_t hash_value, const intptr_t string_data,
                           const int string_length ) {
        int       result      = 0;
        const int entry_count = context->m_entry_count;

        if ( entry_count <= 0 ) {
            goto ADD_NEW_ENTRY;
        }

        // Search for existing entry
        common::hash_entry_t *entries = reinterpret_cast< common::hash_entry_t * >( context->m_entries_buffer );
        while ( entries[ result ].m_hash_value != hash_value ) {
            ++result;
            if ( result >= entry_count )
                goto ADD_NEW_ENTRY;
        }

        // Found existing entry - increment reference count
        result *= 20; // Each entry is 20 bytes
        ++entries[ result / 20 ].m_reference_count;
        return result;

    ADD_NEW_ENTRY:
        if ( entry_count < 500 ) { // Max 500 entries
            common::hash_entry_t *new_entry = &reinterpret_cast< common::hash_entry_t * >( context->m_entries_buffer )[ entry_count ];

            new_entry->m_hash_value      = hash_value;
            new_entry->m_reference_count = 1;
            new_entry->m_string_pointer  = 0;
            new_entry->m_string_length   = string_length;
            new_entry->m_flags           = 0;

            result = static_cast< intptr_t >( context->m_entries_buffer );

            if ( string_data ) {
                result = string_length + context->m_string_buffer_used + 1;
                if ( result < 0x4000 ) { // 16KB limit
                    // Copy string to buffer
                    copy_memory_vac( reinterpret_cast< unsigned char * >( context->m_strings_buffer ), string_data, string_length );
                    *( context->m_strings_buffer + string_length ) = 0; // Null terminate

                    new_entry->m_string_pointer    = static_cast< uint32_t >( reinterpret_cast< uintptr_t >( context->m_strings_buffer ) );
                    context->m_strings_buffer      = context->m_strings_buffer + string_length + 1;
                    result                         = string_length + 1;
                    context->m_string_buffer_used += string_length + 1;
                }
            }

            ++context->m_entry_count;
        }

        return result;
    }

    void *expand_dynamic_array( common::hash_lookup_array_t *array ) {
        char *current_end = static_cast< char * >( array->m_current_end );
        if ( array->m_buffer_end == current_end ) {
            void *old_buffer     = array->m_data_buffer;
            void *new_end        = current_end + 128;
            array->m_current_end = new_end;

            // Reallocate buffer
            const HANDLE heap = GetProcessHeap( );
            void        *new_buffer;
            if ( old_buffer ) {
                new_buffer = HeapReAlloc( heap, 0, old_buffer, 4 * reinterpret_cast< size_t >( new_end ) );
            } else {
                new_buffer = HeapAlloc( heap, 0, 4 * reinterpret_cast< size_t >( new_end ) );
            }
            array->m_data_buffer = new_buffer;
            return new_buffer;
        }
        return array->m_data_buffer;
    }

    uint32_t add_hash_to_lookup( common::hash_lookup_array_t *array, const uint32_t hash_value ) {
        expand_dynamic_array( array );

        uint32_t    *data   = static_cast< uint32_t * >( array->m_data_buffer );
        const size_t index  = reinterpret_cast< size_t >( array->m_buffer_end );
        data[ index ]       = hash_value;
        array->m_buffer_end = static_cast< char * >( array->m_buffer_end ) + 1;

        return hash_value;
    }

    uint32_t __stdcall convert_filetime_to_seconds( const uint64_t filetime_low, const uint64_t filetime_high, const uint32_t divisor_low,
                                                    const uint32_t divisor_high ) {
        const uint64_t filetime = ( filetime_high << 32 ) | filetime_low;
        const uint64_t divisor  = ( static_cast< uint64_t >( divisor_high ) << 32 ) | divisor_low;

        if ( divisor_high ) {
            // Complex division for large divisor
            uint32_t high_part = divisor_high;
            uint32_t low_part  = divisor_low;
            uint64_t dividend  = filetime;

            // Normalize divisor
            do {
                const bool carry   = high_part & 1;
                high_part        >>= 1;
                low_part           = ( low_part >> 1 ) | ( carry << 31 );
                dividend         >>= 1;
            } while ( high_part );

            uint32_t       quotient = static_cast< uint32_t >( dividend / low_part );
            const uint64_t product  = quotient * divisor;

            // Adjust if product is too large
            if ( product > filetime ) {
                --quotient;
            }
            return quotient;
        } else {
            // Simple division
            return static_cast< uint32_t >( filetime / divisor_low );
        }
    }

} // namespace vac::utils