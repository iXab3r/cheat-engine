#include "logging.h"
#include <TraceLoggingProvider.h>
#include <evntrace.h>
#include <ntifs.h>

// Define the TraceLogging provider in exactly one translation unit
//6bb0f0b0-8c4b-4e0d-9e65-4a2f1f8b2d3a
TRACELOGGING_DEFINE_PROVIDER(
    g_DBKProvider,
    "EA.DEA64",
    (0x6bb0f0b0, 0x8c4b, 0x4e0d, 0x9e, 0x65, 0x4a, 0x2f, 0x1f, 0x8b, 0x2d, 0x3a));
