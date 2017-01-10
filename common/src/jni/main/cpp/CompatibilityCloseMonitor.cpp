#include "CompatibilityCloseMonitor.h"

#if defined(CONSCRYPT_UNBUNDLED) && !defined(CONSCRYPT_OPENJDK)

#include <dlfcn.h>

using namespace conscrypt;

CompatibilityCloseMonitor::acm_ctor_func CompatibilityCloseMonitor::asyncCloseMonitorConstructor = nullptr;
CompatibilityCloseMonitor::acm_dtor_func CompatibilityCloseMonitor::asyncCloseMonitorDestructor = nullptr;

void CompatibilityCloseMonitor::init() {
    void *lib = dlopen("libjavacore.so", RTLD_NOW);
    if (lib != nullptr) {
        asyncCloseMonitorConstructor = (acm_ctor_func) dlsym(lib, "_ZN24AsynchronousCloseMonitorC1Ei");
        asyncCloseMonitorDestructor = (acm_dtor_func) dlsym(lib, "_ZN24AsynchronousCloseMonitorD1Ev");
    }
}

#endif // CONSCRYPT_UNBUNDLED && !CONSCRYPT_OPENJDK
