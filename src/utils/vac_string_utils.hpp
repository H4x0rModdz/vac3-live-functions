#pragma once
#include <cstdint>
#include <windows.h>

namespace vac::utils {
    /**
     * @brief Copy memory implementation
     * @param dest Destination buffer
     * @param source Source address (as offset)
     * @param length Number of bytes to copy
     * @return Destination pointer
     */
    unsigned char *__cdecl copy_memory_vac( unsigned char *dest, intptr_t source, int length );

    /**
     * @brief Zero memory implementation
     * @param buffer Buffer to zero
     * @param fill_value Fill value
     * @param size Buffer size
     * @return Buffer pointer
     */
    char *__cdecl zero_memory_vac( char *buffer, char fill_value, uint32_t size );

    /**
     * @brief Wide string copy with path replacement
     * @param dest Destination buffer
     * @param source Source wide string
     * @return Destination pointer
     */
    unsigned char * copy_wide_string_vac( unsigned char *dest, const WCHAR *source );
} // namespace vac::utils