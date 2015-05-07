#include <android/log.h>
#define ALOG(priority, tag, ...) \
            __android_log_print(ANDROID_##priority, tag, __VA_ARGS__)
#define ALOGD(...) \
            __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define ALOGE(...) \
            __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

#define __ALOGV(...) __android_log_print(ANDROID_LOG_VERBOSE, LOG_TAG, __VA_ARGS__)
#if LOG_NDEBUG
#define ALOGV(...) do { if (0) { __ALOGV(__VA_ARGS__); } } while (0)
#else
#define ALOGV(...) __ALOGV(__VA_ARGS__)
#endif
