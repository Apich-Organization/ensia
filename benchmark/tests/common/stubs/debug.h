/**
 * @file debug.h
 * @brief Debug/trace stub for benchmark tests — all macros are no-ops
 */
#ifndef _DEBUG_H
#define _DEBUG_H

/* CycloneCRYPTO debug macros — suppressed in benchmark builds */
#define DEBUG_BREAKPOINT()     ((void)0)
#define TRACE_FATAL(fmt, ...)  ((void)0)
#define TRACE_ERROR(fmt, ...)  ((void)0)
#define TRACE_WARNING(fmt, ...) ((void)0)
#define TRACE_INFO(fmt, ...)   ((void)0)
#define TRACE_DEBUG(fmt, ...)  ((void)0)
#define TRACE_VERBOSE(fmt, ...) ((void)0)

/* MPI / ECC trace macros — suppressed in benchmark builds */
#define TRACE_DEBUG_MPI(label, mpi)         ((void)0)
#define TRACE_DEBUG_EC_POINT(label, p)      ((void)0)
#define TRACE_DEBUG_EC_SCALAR(label, s, n)  ((void)0)

#endif /* _DEBUG_H */
