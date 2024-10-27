#! /bin/bash
#
#  Copyright (C) 2024 The Android Open Source Project
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

# Builds and locally publishes an uber jar for local architectures.
#
# Normally an uber jar contains JNI binaries for all supported
# platforms, but that requires those binaries to be built somewhere.
# This script infers the binary types that can be built locally and
# adds only those to the jar.  This allows end to end testing of the
# build process as well as testing of the uberjar against multiple
# Java versions (see testLocalUber.sh)


CONSCRYPT_HOME="${CONSCRYPT_HOME:-$HOME/src/conscrypt}"
BUILD="$CONSCRYPT_HOME/build.gradle"
M2_REPO="${M2_REPO:-$HOME/.m2/repository}"
PUBLISH_DIR="${M2_REPO}/org/conscrypt"

die() {
	echo "*** " $@
	exit 1
}

case $(uname -s) in
	Darwin)
		CLASSIFIERS="osx-x86_64,osx-aarch_64"
		;;
	Linux)
		CLASSIFIERS="linux-x86_64"
		;;
	*)
		die "TODO: Finish this switch statement"
		;;
esac

test -f "$BUILD" || die "Conscrypt build file not found.  Check CONSCRYPT_HOME."

VERSION=$(sed -nE 's/^ *version *= *"(.*)"/\1/p' $BUILD)
test "$VERSION" || die "Unable to figure out Conscrypt version."
echo "Conscrypt version ${VERSION}."

UBERJAR="$PUBLISH_DIR/conscrypt-openjdk-uber/$VERSION/conscrypt-openjdk-uber-${VERSION}.jar"

cd "$CONSCRYPT_HOME"
./gradlew :conscrypt-openjdk:publishToMavenLocal \
		  --console=plain
./gradlew :conscrypt-openjdk-uber:publishToMavenLocal \
		  -Dorg.conscrypt.openjdk.uberJarClassifiers="$CLASSIFIERS" \
		  -Dorg.conscrypt.openjdk.buildUberJar=true \
		  --console=plain

test -f "$UBERJAR" || die "Uber jar not published."
ls -l "$UBERJAR"
