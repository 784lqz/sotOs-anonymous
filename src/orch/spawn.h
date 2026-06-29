#pragma once

#include <stddef.h>

/* SP2-migración · staging buffer for loading binaries > the static buffer. */
void *orch_spawn_stage(size_t bytes);
