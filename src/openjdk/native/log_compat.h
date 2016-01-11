#define ALOGD(...) \
            /* __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__) */
#define ALOGE(...) \
            /* __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__) */
#define ALOGV(...) \
            /* __android_log_print(ANDROID_LOG_VERBOSE, LOG_TAG, __VA_ARGS__) */
