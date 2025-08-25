#pragma once
#include <windows.h>

namespace vac::utils {
    /**
     * @brief Compare strings case-insensitive
     * @param string1 First string
     * @param string2 Second string
     * @param count Number of characters to compare
     * @return 0 if equal, non-zero if different
     */
    int __fastcall compare_string_case_insensitive( PCNZWCH string1, PCNZWCH string2, int count );

    /**
     * @brief Find last backslash in path
     * @param path Path string
     * @return Pointer to character after last backslash
     */
    LPCWSTR find_last_backslash( LPCWSTR path );

    /**
     * @brief Convert Unicode to ANSI
     * @param unicode_string Unicode input string
     * @param ansi_buffer ANSI output buffer
     * @return Non-zero on success
     */
    int __fastcall convert_unicode_to_ansi( intptr_t unicode_string, intptr_t ansi_buffer );

    /**
     * @brief Normalize process path
     * @param process_path Process path to normalize
     * @param unused_param Unused parameter
     * @return 1 on success, 0 on failure
     */
    char __stdcall normalize_process_path( PCNZWCH process_path, int unused_param );
} // namespace vac::utils