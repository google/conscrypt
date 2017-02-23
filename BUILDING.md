Building Conscrypt
==================

Before you begin, you'll first need to properly configure the [Prerequisites](#Prerequisites) as
described below.

Then to build, run:

```bash
$ ./gradlew build
```

To install the artifacts to your Maven local repository for use in your own project, run:

```bash
$ ./gradlew install
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
This assumes that you have Microsoft Visual Studio 2015 installed along
with Windows 8.1 SDK and your machine is capable of compiling 64-bit.
Visual Studio 2015 sets the `VS140COMNTOOLS` environment variable upon
installation.

To build in 64-bit mode, set up with this command line:

```bat
call "%VS140COMNTOOLS%\..\..\VC\vcvarsall.bat" amd64 8.1
mkdir build64
cd build64
```

To build in 32-bit mode, set up with this command line:

```bat
call "%VS140COMNTOOLS%\..\..\VC\vcvarsall.bat" x86 8.1
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

