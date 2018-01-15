#ifndef CPU_INFO_H
#define CPU_INFO_H


#include <stdint.h>

//////////////////////////////////////
// Error config definitions
//////////////////////////////////////

#define CPUI_ERRORS \
    CPUI_ERRORDEF(NOT_IMPLEMENTED) \
    CPUI_ERRORDEF(SYSCALL)

#define CPUI_ERRORDEF(err) CPUI_ERROR_##err,

typedef enum  {
    CPUI_SUCCESS = 0,
    CPUI_ERRORS
    CPUI_UNKNOWN
} cpui_error_t;

#undef CPUI_ERRORDEF

#define CPUI_ERRORDEF(err) "CPUI_ERROR_" #err,

const char* const cpui_error_strings[] = {
    "CPUI_SUCCESS",
    CPUI_ERRORS
    "CPUI_UNKNOWN"
};

//////////////////////////////////////
// Header section
//////////////////////////////////////

typedef struct {
    uint32_t physical_cores;
    uint32_t logical_cores;
} cpui_result;


cpui_error_t cpui_get_info(cpui_result* result);


#endif // CPU_INFO_H

#ifdef CPU_INFO_IMPLEMENTATION


//////////////////////////////////////
// Config info for OS and platform
//////////////////////////////////////

#define CPUI_OS_MACOS 0
#define CPUI_OS_IOS 0
#define CPUI_OS_ANDROID 0
#define CPUI_OS_WINDOWS 0
#define CPUI_OS_LINUX 0

#if defined(__APPLE__) && defined(__MACH__)

#include <TargetConditionals.h>

#if TARGET_IPHONE_SIMULATOR == 1

#undef CPUI_OS_IOS
#define CPUI_OS_IOS 1

#elif TARGET_OS_IPHONE == 1

#undef CPUI_OS_IOS
#define CPUI_OS_IOS 1

#elif TARGET_OS_MAC == 1

#undef CPUI_OS_MACOS
#define CPUI_OS_MACOS 1

#endif
#elif defined(__WIN32__) || defined(__WINDOWS__) || defined(_WIN64) \
 || defined(_WIN32) || defined(_WINDOWS) || defined(__TOS_WIN__)
#undef CPUI_OS_WINDOWS

#define CPUI_OS_WINDOWS 1

#elif defined(__linux__) || defined(__linux) || defined(linux_generic)

#undef CPUI_OS_LINUX
#define CPUI_OS_LINUX 1

#elif defined(__ANDROID__)

#undef CPUI_OS_ANDROID
#define CPUI_OS_ANDROID 1
#define CPUI_OS_ANDROID_API_LEVEL = __ANDROID_API__;

#endif

//////////////////////////////////////
// Implementation section
//////////////////////////////////////

#include <stddef.h>

#if CPUI_OS_MACOS == 1

#include <sys/sysctl.h>

cpui_error_t cpui_get_info(cpui_result* result)
{
    //Assuming an Intel processor with CPUID leaf 11
    size_t psize = sizeof(result->physical_cores);
    size_t lsize = sizeof(result->logical_cores);

    int err = sysctlbyname("hw.physicalcpu", &result->physical_cores, &psize, NULL, 0);
    if (err) {
        return CPUI_ERROR_SYSCALL;
    }

    err = sysctlbyname("hw.logicalcpu", &result->logical_cores, &lsize, NULL, 0);
    if (err) {
        return CPUI_ERROR_SYSCALL;
    }

    return CPUI_SUCCESS;
}


#elif CPUI_OS_WINDOWS == 1

cpui_error_t cpui_get_info(cpui_result* result)
{
    SYSTEM_INFO sysinfo;

    return CPUI_SUCCESS;
}


#else


int cpui_get_info(cpui_result* result)
{
    return CPUI_ERROR_NOT_IMPLEMENTED;
}


#endif // conditional info


#endif // CPU_INFO_IMPLEMENTATION