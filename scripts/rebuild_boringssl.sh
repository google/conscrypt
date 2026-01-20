#! /bin/bash
#
#  Copyright (C) 2025 The Android Open Source Project
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

# Rebuilds BoringSSL from scratch for supported architectures,
# optionally performing a `git pull` first to update it.


UPSTREAM="https://github.com/google/boringssl.git"
MAIN="main"

fail() {
        echo "*** FAILED: " $@
        exit 1
}

usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

--clone   Clone BoringSSL git repository if not already present
--update  Resync from upstream before building
--clean   Clean before building

EOF
    exit 0
}

test "$BORINGSSL_HOME" || fail "Please set BORINGSSL_HOME."


CLONE=
UPDATE=
CLEAN=
while [ "$1" ]; do
    case "$1" in
        --clone)
            CLONE=true
            ;;

        --update | --pull)
            UPDATE=true
            ;;

        --clean | --fresh)
            CLEAN=true
            ;;

        *)
            usage
            95
            ;;
    esac
    shift
done

if [ "$CLONE" ]; then
    echo "Cloning BoringSSL from ${UPSTREAM}."

    test -d "$BORINGSSL_HOME" && fail "$BORINGSSL_HOME already exists"
    PARENT="$(dirname $BORINGSSL_HOME)"
    cd "$PARENT" || fail "Cannot access parent directory $PARENT"
    git clone "$UPSTREAM" "$BORINGSSL_HOME" || fail "Unable to clone BoringSSL"
    UPDATE=
    CLEAN=true
fi

cd "$BORINGSSL_HOME" || fail "Cannot access $BORINGSSL_HOME"

if [ "$UPDATE" ]; then
    echo "Updating BoringSSL."
    git checkout "$MAIN"
    git pull
fi

run_cmake() {
    local BUILD_DIR="${BORINGSSL_HOME}/$1"
    local EXTRA_CMAKE_FLAGS="$2"

    if [ "$CLEAN" ]; then
        echo "Removing $BUILD_DIR"
        rm -rf "$BUILD_DIR"
    fi
    mkdir -p "$BUILD_DIR" || fail "Unable to create $BUILD_DIR"
    cd "$BUILD_DIR" || fail "Unable to access $BUILD_DIR"
    echo "Running cmake."
    cmake -DCMAKE_POSITION_INDEPENDENT_CODE=TRUE -DCMAKE_BUILD_TYPE=Release $EXTRA_CMAKE_FLAGS \
          -GNinja .. || fail "cmake failed."
    echo "Building BoringSSL in ${BUILD_DIR}."
    ninja
}

case "$(uname -s)" in
    Darwin)
        run_cmake build.x86 "-DCMAKE_ASM_FLAGS=-Wa,--noexecstack -DCMAKE_OSX_ARCHITECTURES=x86_64"
        run_cmake build.arm "-DCMAKE_ASM_FLAGS=-Wa,--noexecstack -DCMAKE_OSX_ARCHITECTURES=arm64"
        ;;

    Linux)
        run_cmake build64 "-DCMAKE_ASM_FLAGS=-Wa,--noexecstack"
        ;;

    MINGW64*)
        run_cmake build64 "-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded"
        ;;

    *)
        fail "Please follow the manual build instructions."
        ;;
esac
