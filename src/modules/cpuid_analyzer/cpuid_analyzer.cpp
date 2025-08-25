#include "cpuid_analyzer.hpp"
#include <intrin.h>

namespace vac::modules::cpuid_analyzer {

    // Global CPUID support detection flag - exact VAC location dword_100067D0
    static uint32_t g_cpuid_support_flag = 0;

    // CPUID function lookup table - exact VAC data at dword_10006570 and off_10006574
    constexpr common::cpuid_function_descriptor_t g_cpuid_function_table[] = {
        { 0x40000000, validate_hypervisor_info }, // Hypervisor information function
        {          0,                  nullptr }  // Terminator
    };

    int __fastcall execute_cpuid_instruction( uint32_t *eax_function_code, uint32_t *ebx_output, uint32_t *ecx_output,
                                              uint32_t *edx_output ) {
        // Check if CPUID support has been tested
        if ( !g_cpuid_support_flag ) {
            uint32_t eflags_test_bit = 0x200000; // CPUID flag (bit 21)

            uint32_t original_eflags = __readeflags( );
            uint32_t saved_eflags    = original_eflags;

            uint32_t modified_eflags = __readeflags( );
            __writeeflags( modified_eflags ^ eflags_test_bit );
            uint32_t tested_eflags = __readeflags( );

            __writeeflags( saved_eflags );

            // Check if CPUID flag could be toggled
            if ( ( ( modified_eflags ^ tested_eflags ) & eflags_test_bit ) == 0 ) {
                return 0; // CPUID not supported
            }

            g_cpuid_support_flag = 1; // Mark CPUID as supported
        }

        // Execute CPUID instruction
        uint32_t eax_value = *eax_function_code;
        uint32_t ebx_value, ecx_value, edx_value;

        // Inline assembly for CPUID instruction
        __asm {
            mov eax, eax_value
            cpuid
            mov ebx_value, ebx
            mov ecx_value, ecx  
            mov edx_value, edx
            mov eax_value, eax
        }

        // Store results in output parameters
        *eax_function_code = eax_value;
        *ebx_output        = ebx_value;
        *ecx_output        = ecx_value;
        *edx_output        = edx_value;

        return 1; // Success
    }

    int __fastcall query_cpuid_function( common::cpuid_analysis_context_t *analysis_context, uint32_t *entry_count, uint32_t *first_output,
                                         const uint32_t function_code, bool( __cdecl *validator )( int context, int entry_offset ) ) {
        const int       entry_offset   = 24 * ( *entry_count ) + 40;
        static uint32_t sub_function   = 0;
        static int      context_offset = reinterpret_cast< int >( analysis_context );

        common::cpu_info_entry_t *current_entry = &analysis_context->m_cpu_entries[ *entry_count ];
        common::cpu_info_entry_t *next_entry    = current_entry + 2; // Points to ECX/EDX storage

        if ( *entry_count >= 169 ) {
            return 1; // Entry count limit exceeded
        }

        // Initialize CPU info entry
        current_entry->m_eax_value     = function_code; // Store function code in EAX
        next_entry->m_eax_value        = function_code; // Duplicate for validation
        current_entry->m_ebx_value     = sub_function;  // Sub-function/leaf (typically 0)
        current_entry->m_function_code = sub_function;  // Additional sub-function storage

        const uint32_t incremented_sub_function = sub_function + 1;

        // Execute CPUID instruction
        if ( !execute_cpuid_instruction( &current_entry->m_ecx_value, &current_entry->m_edx_value, &current_entry->m_function_code,
                                         &current_entry->m_sub_function ) ) {
            return 2; // CPUID instruction failed
        }

        // Store first output for caller (typically EBX value)
        if ( !function_code ) { // For function 0, return max supported function
            *first_output = next_entry->m_eax_value;
        }

        ++( *entry_count );

        // Call validator function if provided
        if ( validator ) {
            const int validation_result = validator( context_offset + entry_offset, reinterpret_cast< int >( current_entry ) );
            sub_function                = incremented_sub_function;
            context_offset              = reinterpret_cast< int >( analysis_context );

            if ( validation_result ) {
                return 0;
            }
        }

        return 0;
    }

    bool __cdecl validate_hypervisor_info( [[maybe_unused]] int context_offset, const int entry_offset ) {
        // Extract ECX value from CPU info entry
        // entry_offset + 8 points to ECX register value
        const uint8_t ecx_lower_bits = *reinterpret_cast< uint8_t * >( entry_offset + 8 );

        // Check if any of the lower 4 bits are set (hypervisor features)
        return ( ecx_lower_bits & 0xF ) != 0;
    }

    int analyze_cpu_information( common::cpuid_analysis_context_t *analysis_context ) {
        int      analysis_result      = 0;
        uint32_t first_output         = 0;
        int      function_range_index = 0;

        // Process three main CPUID function ranges
        while ( function_range_index < 3 ) {
            // Get base function code for current range from lookup table
            // Offset 28 in context + function_range_index points to base function codes
            const uint32_t base_function_code
                = reinterpret_cast< uint32_t * >( reinterpret_cast< char * >( analysis_context ) + 28 )[ function_range_index ];

            uint32_t current_function = base_function_code;

            // Query functions in current range
            do {
                uint32_t validator_function_ptr = 0;

                // Look up validator function in descriptor table
                for ( uint32_t lookup_index = 0; lookup_index < 20; lookup_index += 2 ) {
                    if ( current_function < g_cpuid_function_table[ lookup_index / 2 ].m_function_code ) {
                        break; // Function not found in table
                    }
                    if ( current_function == g_cpuid_function_table[ lookup_index / 2 ].m_function_code ) {
                        validator_function_ptr = reinterpret_cast< uint32_t >( g_cpuid_function_table[ lookup_index / 2 ].m_validator );
                        break;
                    }
                }

                // Query CPUID function with found validator
                const int query_result
                    = query_cpuid_function( analysis_context, &analysis_context->m_entry_count, &first_output, current_function,
                                            reinterpret_cast< bool( __cdecl * )( int, int ) >( validator_function_ptr ) );

                // Process query result
                if ( query_result ) {
                    const int result_code = query_result - 1;
                    if ( result_code ) {
                        if ( result_code == 1 ) {
                            analysis_result = 30; // Hypervisor/virtualization detected
                        } else {
                            analysis_result = -1; // Unexpected error
                        }
                    } else {
                        analysis_result = 234; // Critical CPU features detected
                    }
                    goto ANALYSIS_COMPLETE;
                }

                ++current_function;

            } while ( current_function <= base_function_code ); // Continue in range

            ++function_range_index; // Move to next function range
        }

    ANALYSIS_COMPLETE:
        // Store analysis result in context - exact VAC memory location
        analysis_context->m_analysis_result = analysis_result;
        return analysis_result;
    }

} // namespace vac::modules::cpuid_analyzer