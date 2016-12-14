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
export BORINGSSL_HOME $PWD
```

##### Building on Linux/OS-X
```bash
mkdir build
cd build
cmake -DCMAKE_POSITION_INDEPENDENT_CODE=TRUE \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_ASM_FLAGS=-Wa,\
      --noexecstack \
      -GNinja ..
ninja
```

##### Building on Windows
This assumes that you have

```bash
mkdir build
cd build
cmake -DCMAKE_POSITION_INDEPENDENT_CODE=TRUE \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_C_FLAGS_RELEASE=/MT \
      -DCMAKE_CXX_FLAGS_RELEASE=/MT \
      -GNinja ..
ninja
```

