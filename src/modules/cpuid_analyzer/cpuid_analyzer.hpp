#pragma once

#include "../../common/types.hpp"
#include <cstdint>

namespace vac::modules::cpuid_analyzer {
    /**
     * @brief Execute CPUID instruction and retrieve CPU information
     *
     * This function performs the low-level CPUID instruction execution with CPU feature detection.
     * It first checks if the CPU supports CPUID by testing the CPUID flag in EFLAGS register.
     *
     * The function uses inline assembly to:
     * 1. Test EFLAGS bit 21 (CPUID support flag) by toggling it
     * 2. Execute CPUID instruction with the provided function code
     * 3. Return all four register values (EAX, EBX, ECX, EDX)
     *
     * @param eax_function_code Pointer to EAX input (CPUID function code), receives EAX output
     * @param ebx_output Pointer to receive EBX register output
     * @param ecx_output Pointer to receive ECX register output
     * @param edx_output Pointer to receive EDX register output
     * @return 1 if CPUID is supported and executed successfully, 0 if CPU doesn't support CPUID
     *
     * @note Uses global flag dword_100067D0 to cache CPUID support detection
     */
    int __fastcall execute_cpuid_instruction( uint32_t *eax_function_code, uint32_t *ebx_output, uint32_t *ecx_output,
                                              uint32_t *edx_output );

    /**
     * @brief Query specific CPUID function and store results
     *
     * This function queries a specific CPUID function code and stores the results in the analysis context.
     * It handles the CPUID execution, result validation, and entry management.
     *
     * The function:
     * 1. Calculates the storage offset for the new CPU info entry (24 bytes each)
     * 2. Checks if the entry count limit (169 entries) has been reached
     * 3. Initializes the CPU info entry with function codes and sub-function
     * 4. Executes CPUID instruction to get register values
     * 5. Stores results in the cpu_entries array
     * 6. Calls optional validation function if provided
     * 7. Increments entry count on successful execution
     *
     * @param analysis_context Pointer to CPUID analysis context structure
     * @param entry_count Pointer to current entry count, will be incremented
     * @param first_output Pointer to receive first CPUID output (typically EBX)
     * @param function_code CPUID function code to query (EAX input)
     * @param validator Optional validation function pointer, can be nullptr
     * @return 0 on success
     * @return 1 if entry count limit exceeded (>= 169 entries)
     * @return 2 if CPUID instruction failed (CPU doesn't support CPUID)
     */
    int __fastcall query_cpuid_function( common::cpuid_analysis_context_t *analysis_context, uint32_t *entry_count, uint32_t *first_output,
                                         uint32_t function_code, bool( __cdecl *validator )( int context, int entry_offset ) );

    /**
     * @brief Hypervisor detection validator
     *
     * This function validates CPUID results for hypervisor detection purposes.
     * It checks the ECX register from CPUID function 0x40000000 (hypervisor info).
     *
     * The hypervisor presence is detected by checking if any of the lower 4 bits
     * in the ECX register are set, which indicates hypervisor-specific features.
     *
     * @param context_offset Offset to analysis context (unused in validation)
     * @param entry_offset Offset to the CPU info entry being validated
     * @return true if hypervisor features detected (ECX & 0xF != 0)
     * @return false if no hypervisor features detected
     */
    bool __cdecl validate_hypervisor_info( int context_offset, int entry_offset );

    /**
     * @brief Perform comprehensive CPUID analysis
     *
     * This is the main CPUID analysis function that queries multiple CPU information categories.
     * It systematically checks different CPUID function ranges and validates the results.
     *
     * The function performs analysis in these stages:
     * 1. BASIC CPU INFO: Queries standard CPUID functions (0x0 - 0x1F range typically)
     * 2. HYPERVISOR INFO: Queries hypervisor CPUID functions (0x40000000 range)
     * 3. EXTENDED CPU INFO: Queries extended CPUID functions (0x80000000 range)
     *
     * For each function range, it:
     * - Looks up the function code in the descriptor table (dword_10006570)
     * - Finds the associated validator function (off_10006574)
     * - Queries the CPUID function and validates results
     * - Sets appropriate result codes based on validation outcomes
     *
     * Result codes:
     * - 0: Successful analysis with no issues detected
     * - 30: Specific detection result (hypervisor/virtualization detected)
     * - 234: Critical detection result (specific CPU features detected)
     * - -1: Analysis error or unexpected validation result
     *
     * @param analysis_context Pointer to CPUID analysis context structure
     * @return Analysis result code indicating findings
     *
     * @note The function uses a lookup table at dword_10006570 for function codes
     *       and off_10006574 for corresponding validator function pointers
     */
    int analyze_cpu_information( common::cpuid_analysis_context_t *analysis_context );
} // namespace vac::modules::cpuid_analyzer