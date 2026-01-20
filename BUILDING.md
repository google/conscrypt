Building Conscrypt
==================

Before you begin, you'll first need to properly configure the [Prerequisites](#Prerequisites) as
described below.

Then to build, run:

```bash
$ ./gradlew build
```

To publish the artifacts to your Maven local repository for use in your own project, run:

```bash
$ ./gradlew publishToMavenLocal
```

Prerequisites
-------------
Conscrypt requires that you have __Java__, __BoringSSL__ and the __Android SDK__ configured as
described below.

#### Java
The build uses a version of Gradle which requires a __Java 11__ JDK.

#### Android SDK
[Download and install](https://developer.android.com/studio/install.html) the latest Android SDK
and set the `ANDROID_HOME` environment variable to point to the root of the SDK
(e.g. `export ANDROID_HOME=/usr/local/me/Android/Sdk`).

#### BoringSSL
Before you can build BoringSSL, you'll first need to set up its
[prerequisites](https://boringssl.googlesource.com/boringssl/+/HEAD/BUILDING.md#Build-Prerequisites).

Once the environment is properly configured, follow the steps below for your platform.

##### Download
Checkout BoringSSL to a directory of your choice and then build as follows:

```bash
git clone https://boringssl.googlesource.com/boringssl
cd boringssl

# Also need to set an environment variable to point to the installation location.
export BORINGSSL_HOME=$PWD
```

##### Building on Linux
To build the 64-bit version on a 64-bit machine:
```bash
mkdir build64
cd build64
cmake -DCMAKE_POSITION_INDEPENDENT_CODE=TRUE \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_ASM_FLAGS=-Wa,--noexecstack \
      -GNinja ..
ninja
```

You can also use the `rebuild_boringssl.sh` script (see below) to automate this process.

##### Building on macOS.
When building Conscrypt on macOS it will build libraries for both x86 and ARM, and so BoringSSL
must also be built for each of these.

To build the x86_64 version:
```bash
mkdir build.x86
cd build.x86
cmake -DCMAKE_POSITION_INDEPENDENT_CODE=TRUE \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_ASM_FLAGS=-Wa,--noexecstack \
      -DCMAKE_OSX_ARCHITECTURES=x86_64 \
      -GNinja ..
ninja
```

To build the arm64 version:
```bash
mkdir build.arm
cd build.arm
cmake -DCMAKE_POSITION_INDEPENDENT_CODE=TRUE \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_ASM_FLAGS=-Wa,--noexecstack \
      -DCMAKE_OSX_ARCHITECTURES=arm64 \
      -GNinja ..
ninja
```

You can also use the `rebuild_boringssl.sh` script (see below) to automate this process.

##### Building on Windows
This assumes that you have
[Git for Windows](https://gitforwindows.org/) and
[Microsoft Visual Studio 2022](https://visualstudio.microsoft.com/downloads/)
installed.

You'll also need `nasm`, `cmake` and `ninja` which can be usefully
managed via a package tool such as
[Chocolatey](https://chocolatey.org/).

Like Visual Studio 2017, Visual Studio 2022 provides a batch file
to set up the correct environment for the compiler which can be invoked
as follows (assuming a default installation):
```bat
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x86_amd64
```

However, Visual Studio 2022 also sets up a _Developer Command Prompt_
in Windows Terminal which provides a simpler way of getting the
correct compiler environment, defaulting to 64-bit mode.

After either method, you can run Git for Windows' `bash` to get a
more UNIX like environment with a working compiler.

To build BoringSSL in 64-bit mode from a Command Prompt:
```bat
mkdir build64
cd build64
cmake -DCMAKE_POSITION_INDEPENDENT_CODE=TRUE ^
      -DCMAKE_BUILD_TYPE=Release ^
      -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded ^
      -GNinja ..
ninja
```

32-bit mode is no longer supported on Windows.

If running `bash`, you can use the `rebuild_boringssl` script (see below)
to automate this process.

##### rebuild_boringssl.sh script

The script `scripts/rebuild_boringssl.sh` will build or rebuild BoringSSL
with the correct configuration for the current architecture.

When run with no arguments, the script assumes that `BORINGSSL_HOME` is set
correctly and will re-run `cmake` and `ninja` with the correct arguments.

The following arguments can be used to modify its behaviour:

* `--clone` May only be used if `BORINGSSL_HOME` is set but does not
yet exist.  Will clone BoringSSL from Github and build it.

* `--clean` Delete the current build directly and rebuild from scratch.
* `--pull` or `--update` Updates the source tree to the latest revision and
then builds. Note will not clean old builds unless `--clean` is also specified.

Coverage
--------
To see coverage numbers, run the tests and then execute the jacocoTestReport rule

```bash
./gradlew check jacocoTestReport
```

The report will be placed in `openjdk/build/reports/jacoco/test/html/index.html`
