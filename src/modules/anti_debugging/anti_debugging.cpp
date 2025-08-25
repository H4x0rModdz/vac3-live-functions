#include "anti_debugging.hpp"
#include <Windows.h>
#include <winternl.h>

#pragma intrinsic( __readgsdword )

namespace vac::modules::anti_debugging {
    static uint32_t read_vac_timestamp( ) {
        while ( *reinterpret_cast< volatile uint32_t * >( 0x7FFE0324 ) != *reinterpret_cast< volatile uint32_t * >( 0x7FFE0328 ) ) { }

        const uint32_t tsc_high   = *reinterpret_cast< volatile uint32_t * >( 0x7FFE0320 );
        const uint32_t tsc_low    = *reinterpret_cast< volatile uint32_t * >( 0x7FFE0328 );
        const uint32_t multiplier = *reinterpret_cast< volatile uint32_t * >( 0x7FFE0004 );
        const uint32_t base       = *reinterpret_cast< volatile uint32_t * >( 0x7FFE0000 );

        if ( tsc_high | tsc_low ) {
            return multiplier * ( tsc_low << 8 ) + static_cast< uint32_t >( ( static_cast< uint64_t >( tsc_high ) * multiplier ) >> 24 );
        } else {
            return static_cast< uint32_t >( ( static_cast< uint64_t >( multiplier ) * base ) >> 24 );
        }
    }

    int antidebug_check( [[maybe_unused]] void *context, uint32_t *out_buffer, uint32_t *out_size ) {
        if ( !out_buffer || !out_size )
            return 0;

        // memset32
        for ( int i = 0; i < 8; ++i )
            out_buffer[ i ] = 0;

        *out_size       = 32;
        out_buffer[ 4 ] = 0x34E08400;

        const uint32_t t1  = read_vac_timestamp( );
        out_buffer[ 5 ]   ^= ( ( t1 >> 7 ) + 255 ) & 0xFFFFFF00;

        // BeingDebugged from PEB
        const PPEB peb  = NtCurrentTeb( )->ProcessEnvironmentBlock;
        out_buffer[ 6 ] = peb->BeingDebugged;

        // Real VAC shellcode in .data section: 0xB8 XX XX XX XX C3 → mov eax, imm32; ret
        // CALL code at 0x10005000
        const uint32_t shellcode_result  = reinterpret_cast< uint32_t( __cdecl * )( ) >( reinterpret_cast< void * >( 0x10005000 ) )( );
        out_buffer[ 5 ]                 ^= shellcode_result;

        const uint32_t t2  = read_vac_timestamp( );
        out_buffer[ 5 ]   ^= ( ( t2 >> 7 ) + 255 ) & 0xFFFFFF00;

        return 0;
    }
} // namespace vac::modules::anti_debugging