#!/usr/bin/env bash

if (( BASH_VERSINFO[0] < 3 )); then
  echo "Must be running BASH version 3 or newer!"
  exit 1
fi

if [[ -z $TOP ]]; then \
  echo "You must do envsetup beforehand."
  exit 1
fi

# We are currently in frameworks/rs, so compute our top-level directory.
MY_ANDROID_DIR="$TOP"
cd "$MY_ANDROID_DIR"

if [[ $OSTYPE != *linux* ]]; then \
  echo "Only works on Linux."
  exit 1
fi

SHORT_OSNAME=linux
SONAME=so
# Target architectures and their system library names.
declare -a TARGETS=(generic_armv5 aosp_arm aosp_mips aosp_x86)
declare -a ABI_NAMES=(armeabi armeabi-v7a mips x86)
declare -a SYS_NAMES=(generic_armv5 generic generic_mips generic_x86)
declare -i NUM_CORES="$(awk '/^processor/ { i++ } END { print i }' /proc/cpuinfo)"

echo "Using $NUM_CORES cores"

# Turn off the build cache and make sure we build all of LLVM from scratch.
#export ANDROID_USE_BUILDCACHE=false

# PREBUILTS_DIR is where we want to copy our new files to.
PREBUILTS_DIR="$MY_ANDROID_DIR/prebuilts/conscrypt/"

print_usage() {
  echo "USAGE: $0 [-h|--help] [-n|--no-build] [-x]"
  echo "OPTIONS:"
  echo "    -h, --help     : Display this help message."
  echo "    -n, --no-build : Skip the build step and just copy files."
  echo "    -x             : Display commands before they are executed."
}

build_libs() {
  local t="$1"
  echo Building for target $t
  cd $MY_ANDROID_DIR
  WITH_HOST_DALVIK=false make -j32 PRODUCT-$t-userdebug APP-conscrypt_unbundled-libconscrypt_jni || exit 1
}

# Build everything by default
build_me=1

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      print_usage
      exit 0
      ;;
    -n|--no-build)
      build_me=0
      ;;
    -x)
      # set lets us enable bash -x mode.
      set -x
      ;;
    *)
      echo Unknown argument: "$1"
      print_usage
      exit 99
      break
      ;;
  esac
  shift
done

declare -i i

if [ $build_me -eq 1 ]; then

  echo !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
  echo !!! BUILDING CONSCRYPT PREBUILTS !!!
  echo !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

  source build/envsetup.sh

  for (( i=0; i < ${#TARGETS[@]}; i++ )); do
    build_libs "${TARGETS[$i]}"
  done

  echo DONE BUILDING CONSCRYPT PREBUILTS

else

  echo SKIPPING BUILD OF CONSCRYPT PREBUILTS

fi

DATE="$(date +"%Y%m%d")"

cd "$PREBUILTS_DIR" || exit 3
repo start "pb_$DATE" .

# Don't copy device prebuilts on Darwin. We don't need/use them.
for (( i=0; i < ${#TARGETS[@]}; i++ )); do
  sys="${SYS_NAMES[$i]}"
  abi="${ABI_NAMES[$i]}"
  sys_lib_dir="$MY_ANDROID_DIR/out/target/product/$sys/system/lib"
  if [[ ! -d "jni/$abi" ]]; then
    mkdir -p "jni/$abi"
  fi
  cp "$sys_lib_dir/libconscrypt_jni.so" "jni/$abi/" || exit 4
done

# javalib.jar
cp "$MY_ANDROID_DIR/out/target/common/obj/JAVA_LIBRARIES/conscrypt_unbundled_intermediates/classes.jar" .
