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
The build requires that you have the `JAVA_HOME` environment variable pointing to a valid JDK.

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

##### Building on Linux/OS-X
To build in the 64-bit version on a 64-bit machine:
```bash
mkdir build64
cd build64
cmake -DCMAKE_POSITION_INDEPENDENT_CODE=TRUE \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_ASM_FLAGS=-Wa,--noexecstack \
      -GNinja ..
ninja
```

To make a 32-bit build on a 64-bit machine:
```base
mkdir build32
cd build32
cmake -DCMAKE_TOOLCHAIN_FILE=../util/32-bit-toolchain.cmake \
      -DCMAKE_POSITION_INDEPENDENT_CODE=TRUE \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_ASM_FLAGS="-Wa,--noexecstack -m32 -msse2" \
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
```

To build in 32-bit mode, set up with this command line:

```bat
call "C:\Program Files (x86)\Microsoft Visual Studio\2017\Community\VC\Auxiliary\Build\vcvarsall.bat" x86
mkdir build32
cd build32
```

In either the 64-bit or 32-bit case, run this afterward:

```bat
cmake -DCMAKE_POSITION_INDEPENDENT_CODE=TRUE ^
      -DCMAKE_BUILD_TYPE=Release ^
      -DCMAKE_C_FLAGS_RELEASE=/MT ^
      -DCMAKE_CXX_FLAGS_RELEASE=/MT ^
      -GNinja ..
ninja
```

Running tests on Java 7
-------------------------
Conscrypt is built with Java 8+, but targets the Java 7 runtime. To run the tests
under Java 7 (or any Java runtime), you can specify the `javaExecutable64` property from the command line.
 This will run all tests under `openjdk` and `openjdk-integ-tests` with the specified
 runtime.

```bash
./gradlew check -DjavaExecutable64=${JAVA7_HOME}/bin/java
```

Coverage
--------
To see coverage numbers, run the tests and then execute the jacocoTestReport rule

```bash
./gradlew check jacocoTestReport
```

The report will be placed in `openjdk/build/reports/jacoco/test/html/index.html`
