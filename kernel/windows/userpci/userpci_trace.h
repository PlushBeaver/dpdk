/* SPDX-License-Identifier: BSD-3-Clause */

/** @file WPP tracing support */

/* Tracing GUID: {5d26ef00-c6dc-4499-b8c3-4555d36620d3} */
#define WPP_CONTROL_GUIDS \
    WPP_DEFINE_CONTROL_GUID( \
        USERPCI_TRACE_GUID, (5d26ef00,c6dc,4499,b8c3,4555d36620d3), \
        \
        WPP_DEFINE_BIT(MYDRIVER_ALL_INFO) \
        WPP_DEFINE_BIT(TRACE_GENERAL) /* Driver- or device-level events. */ \
        WPP_DEFINE_BIT(TRACE_MAPPING) /* Resource mapping events. */ \
        )

#define WPP_FLAG_LEVEL_LOGGER(flag, level) \
    WPP_LEVEL_LOGGER(flag)

#define WPP_FLAG_LEVEL_ENABLED(flag, level) \
    (WPP_LEVEL_ENABLED(flag) && \
     WPP_CONTROL(WPP_BIT_ ## flag).Level >= level)

#define WPP_LEVEL_FLAGS_LOGGER(lvl,flags) \
           WPP_LEVEL_LOGGER(flags)
               
#define WPP_LEVEL_FLAGS_ENABLED(lvl, flags) \
           (WPP_LEVEL_ENABLED(flags) && WPP_CONTROL(WPP_BIT_ ## flags).Level >= lvl)

/* WPP orders static parameters before dynamic parameters.
 * To support the Trace function defined below which sets
 * FLAGS=MYDRIVER_ALL_INFO, a custom macro must be defined
 * to reorder the arguments to what the .tpl configuration
 * file expects.
 */
#define WPP_RECORDER_FLAGS_LEVEL_ARGS(flags, lvl) WPP_RECORDER_LEVEL_FLAGS_ARGS(lvl, flags)
#define WPP_RECORDER_FLAGS_LEVEL_FILTER(flags, lvl) WPP_RECORDER_LEVEL_FLAGS_FILTER(lvl, flags)

/* This comment block is scanned by the trace preprocessor to define
 * tracing functions and macros.

begin_wpp config

FUNC Trace{FLAGS=MYDRIVER_ALL_INFO}(LEVEL, MSG, ...);

USEPREFIX(TraceEvents, "%!FUNC!: ");
FUNC TraceEvents(LEVEL, FLAGS, MSG, ...);

FUNC TraceEventsRaw(LEVEL, FLAGS, MSG, ...);

end_wpp

 */
