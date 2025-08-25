#pragma once

#include <cstdint>

namespace vac::modules::pnp_device_scanner {
    /**
     * @brief Parse hexadecimal string to integer
     *
     * This function converts a hexadecimal string to an integer value.
     * It handles both uppercase and lowercase hex digits and validates input.
     *
     * @param hex_string Pointer to hexadecimal string
     * @param length Length of hex string to parse
     * @param result Pointer to store parsed integer result
     * @return 0 on success
     * @return 2 if null character encountered
     * @return 3 if invalid hex character found
     */
    int __fastcall parse_hex_string( int hex_string, unsigned int length, uint32_t *result );

    /**
     * @brief Enumerate all PnP devices and extract hardware information
     *
     * This is the main PnP device enumeration function that:
     * 1. Uses SetupDiGetClassDevsA to get all present devices
     * 2. Enumerates each device with SetupDiEnumDeviceInfo
     * 3. Gets device description using SetupDiGetDeviceRegistryPropertyA
     * 4. Gets hardware IDs using SetupDiGetDeviceRegistryPropertyA
     * 5. Parses VID/PID/Class codes from hardware ID strings
     * 6. De-duplicates devices based on VID/PID/Class combination
     * 7. Stores unique devices in 8-byte entries
     *
     * The function searches for these patterns in hardware IDs:
     * - "VEN_xxxx" or "VID_xxxx" for Vendor ID
     * - "DEV_xxxx" or "PID_xxxx" for Product ID
     * - "CC_xx", "DevClass_xx", "Class_xx", "SubClass_xx", "Prot_xx" for Class codes
     *
     * It handles both primary detection (using VEN_/DEV_) and fallback detection
     * (using VID_/PID_ and various class code formats).
     *
     * @param context_param Unused parameter (present in original)
     * @param results_buffer Pointer to results structure to fill
     * @param buffer_size Pointer to buffer size (input/output)
     * @return 0 on success, error code on failure
     *
     * @note Maximum 508 devices can be stored due to buffer size limits
     * @note Function uses exact VAC string obfuscation with XOR 0x3E
     */
    int __cdecl enumerate_pnp_devices( void *context_param, char *results_buffer, unsigned int *buffer_size );

    /**
     * @brief Helper function to deobfuscate strings
     * @param obfuscated_string Source obfuscated string
     * @param deobfuscated_buffer Output buffer for deobfuscated string
     * @param length String length
     */
    inline void deobfuscate_string( const char *obfuscated_string, char *deobfuscated_buffer, size_t length ) {
        for ( size_t i = 0; i < length; ++i ) {
            // todo: Make it possible to enter a different xor value, because Valve often uses different encryption keys.
            deobfuscated_buffer[ i ] = obfuscated_string[ i ] ^ 0x3E;
        }
    }
} // namespace vac::modules::pnp_device_scanner