#pragma once
#include <cstdint>
#include <windows.h>

namespace vac::common {
    struct hash_table_context_t;
    struct hash_lookup_array_t;
} // namespace vac::common

namespace vac::utils {

    /**
     * @brief Calculate string hash
     *
     * This function implements the exact hash algorithm used by VAC for string hashing.
     * It converts characters to lowercase and uses a multiplicative hash with base 33.
     *
     * @param string String to hash (unsigned char array)
     * @param length String length in bytes
     * @return Hash value (starts with 1171724434)
     */
    uint32_t __fastcall calculate_string_hash( const unsigned char *string, int length );

    /**
     * @brief Store string data in hash table
     *
     * This function manages a hash table with 20-byte entries. Each entry contains:
     * - Hash value (4 bytes)
     * - String pointer (4 bytes)
     * - String length (4 bytes)
     * - Reference count (4 bytes)
     * - Flags (1 byte) + padding (3 bytes)
     *
     * @param context Hash table context containing entry buffer and string buffer
     * @param hash_value Hash value of the string
     * @param string_data Pointer to string data to store
     * @param string_length Length of string in bytes
     * @return Entry index * 20, or buffer offset
     */
    int store_string_data( common::hash_table_context_t *context, uint32_t hash_value, intptr_t string_data, int string_length );

    /**
     * @brief Expand dynamic array if needed
     *
     * This function expands a dynamic array by 128 elements when the current position
     * reaches the buffer end. Uses HeapAlloc/HeapReAlloc for memory management.
     *
     * @param array Dynamic array context with data buffer and size tracking
     * @return Pointer to reallocated buffer, or existing buffer if no expansion needed
     */
    void * expand_dynamic_array( common::hash_lookup_array_t *array );

    /**
     * @brief Add hash to lookup array
     *
     * This function adds a hash value to a dynamic lookup array. Automatically
     * expands the array if needed using expand_dynamic_array().
     *
     * @param array Hash lookup array context
     * @param hash_value Hash value to add to the array
     * @return The hash value that was added
     */
    uint32_t add_hash_to_lookup( common::hash_lookup_array_t *array, uint32_t hash_value );

    /**
     * @brief Convert FILETIME to seconds
     *
     * This function implements the exact algorithm used by VAC to convert Windows
     * FILETIME (100-nanosecond intervals) to seconds. Handles both simple division
     * and complex 64-bit division when the divisor high part is non-zero.
     *
     * The algorithm includes:
     * - Bit shifting normalization for large divisors
     * - Overflow protection with quotient adjustment
     * - Exact replication of VAC's division logic
     *
     * @param filetime_low Low 32 bits of FILETIME
     * @param filetime_high High 32 bits of FILETIME
     * @param divisor_low Low 32 bits of divisor (typically 10000000 for seconds)
     * @param divisor_high High 32 bits of divisor (typically 0)
     * @return Number of seconds since FILETIME epoch
     */
    uint32_t __stdcall convert_filetime_to_seconds( uint64_t filetime_low, uint64_t filetime_high, uint32_t divisor_low,
                                                    uint32_t divisor_high );

    /**
     * @brief Helper function to allocate memory from process heap
     *
     * Wrapper around HeapAlloc/HeapReAlloc used by the dynamic array functions.
     * Uses GetProcessHeap() to get the default process heap.
     *
     * @param existing_memory Existing memory pointer (nullptr for new allocation)
     * @param new_size New size in bytes
     * @return Pointer to allocated/reallocated memory, or nullptr on failure
     */
    inline LPVOID allocate_from_heap( const LPVOID existing_memory, const SIZE_T new_size ) {
        const HANDLE process_heap = GetProcessHeap( );
        if ( existing_memory ) {
            return HeapReAlloc( process_heap, 0, existing_memory, new_size );
        } else {
            return HeapAlloc( process_heap, 0, new_size );
        }
    }
} // namespace vac::utils