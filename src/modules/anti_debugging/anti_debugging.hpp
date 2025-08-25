#pragma once
#include <cstdint>

namespace vac::modules::anti_debugging {
    int antidebug_check( void *context, uint32_t *out_buffer, uint32_t *out_size );
}