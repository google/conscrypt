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
The build uses a version of Gradle which requires a __Java 11__ JRE to run, however to ensure 
backward compatibility Conscrypt itself is compiled with a __Java 8__ JDK using Gradle's
recent Java toolchain support.  At the least, you will need to install __Java 11__ to run 
Gradle, but if you do not also have __Java 8__ then depending on the OS, Gradle will
try and install it automatically.

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

##### Building on macOS.
When building Conscrypt on macOS it will build libraries for both x86 and ARM, and so BoringSSL
must also be build for each of these.

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


##### Building on Windows
This assumes that you have Microsoft Visual Studio 2017 installed along
with both the Windows 8.1 and 10 SDKs and that your machine is capable of
compiling 64-bit.

Unlike earlier versions, Visual Studio 2017 doesn't appear to set an
environment variable to simplify building from the command line. The
instructions below assume the default installation of the community
edition. To use another edition or a non-standard install path, you'll
need to modify the paths below as appropriate.

To build in 64-bit mode, set up with this command line:

```bat
call "C:\Program Files (x86)\Microsoft Visual Studio\2017\Community\VC\Auxiliary\Build\vcvarsall.bat" x86_amd64
mkdir build64
cd build64
cmake -DCMAKE_POSITION_INDEPENDENT_CODE=TRUE ^
      -DCMAKE_BUILD_TYPE=Release ^
      -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded ^
      -GNinja ..
ninja
```

32-bit mode is no longer supported.

Coverage
--------
To see coverage numbers, run the tests and then execute the jacocoTestReport rule

```bash
./gradlew check jacocoTestReport
```

The report will be placed in `openjdk/build/reports/jacoco/test/html/index.html`
