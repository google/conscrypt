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

# Tests a locally published uber jar against the current Java version using
# the JUnit console test runner (which will be downloaded if not present).
#
# This script has two modes:
#
# BUILD MODE (--build): Builds the test jar using Gradle.  Requires Java 11+.
# Set JAVA_HOME or PATH to point at a Java 11+ JDK before running.
#
#   ./scripts/testLocalUber.sh --build
#
# TEST MODE (default): Runs the tests against whatever Java version is active.
# The test jar must already have been built (via --build).  This mode does not
# invoke Gradle, so any Java version can be used.
#
#   JAVA_HOME=/path/to/java21 ./scripts/testLocalUber.sh
#
# To pass extra JVM arguments to the test process (e.g. system properties),
# set JAVA_OPTS before running:
#
#   JAVA_OPTS="-Djdk.tls.someFlag=false" ./scripts/testLocalUber.sh
#
# Typical workflow for testing against a non-default Java version:
#
#   # 1. Build artifacts (requires publishLocalUber.sh first)
#   JAVA_HOME=/path/to/java11 ./scripts/publishLocalUber.sh
#   JAVA_HOME=/path/to/java11 ./scripts/testLocalUber.sh --build
#
#   # 2. Run tests under the target Java version
#   JAVA_HOME=/path/to/java21 ./scripts/testLocalUber.sh

CONSCRYPT_HOME="${CONSCRYPT_HOME:-$HOME/src/conscrypt}"
BUILD="$CONSCRYPT_HOME/build.gradle"
M2_REPO="${M2_REPO:-$HOME/.m2/repository}"
PUBLISH_DIR="${M2_REPO}/org/conscrypt"
TMPDIR="${TMPDIR:-$HOME/tmp/conscrypt}"
JUNITJAR="$TMPDIR/junit-platform-console-standalone.jar"

fail() {
	echo "*** " $@
	exit 1
}

usage() {
	echo "testLocalUber.sh [args]"
	echo ""
	echo "--build              Build the test jar using Gradle (requires Java 11+)"
	echo "--tests CLASS[#METHOD]"
	echo "                     Run a specific test class or method instead of the"
	echo "                     full suite.  Use fully qualified class names, e.g.:"
	echo "                     org.conscrypt.javax.net.ssl.KeyManagerFactoryTest"
	echo "                     org.conscrypt.SSLEngineTest#test_SSLEngine_beginHandshake"
	echo "                     Note: bypasses suite setup and so Conscrypt is not auto-installed"
	echo "                     as default provider); many tests are unaffected by this."
	echo "-h, --help           Help"
	echo "-v, --verbose        Verbose test output"
	echo "-d, --debug          Wait for debugger on test startup"
	echo ""
	echo "Environment variables:"
	echo "JAVA_OPTS            Extra JVM arguments for the test process, e.g.:"
	echo "                     JAVA_OPTS=\"-Dfoo=bar\" ./scripts/testLocalUber.sh"
	exit 0
}

BUILD_ONLY=false

while [ "$1" ]; do
	case "$1" in
		--build)
			BUILD_ONLY=true
			;;
		--tests)
			shift
			TESTS="$1"
			;;
		-v|--verbose)
			VERBOSE="--details=verbose"
			;;
		-d|--debug)
			JAVADEBUG="-agentlib:jdwp=transport=dt_socket,server=y,suspend=y,address=5005"
			;;
		-h|--help)
			usage
			;;
		*)
			fail "Unknown argument $1 - try --help"
			;;
	esac
	shift
done

mkdir -p "$TMPDIR" || fail "Unable to create ${TMPDIR}."

test -f "$BUILD" || fail "Conscrypt build.gradle file not found.  Check CONSCRYPT_HOME."
VERSION=$(sed -nE 's/^ *version *= *"(.*)"/\1/p' $BUILD)
test "$VERSION" || fail "Unable to figure out Conscrypt version."
echo "Conscrypt version ${VERSION}."

UBERJAR="${PUBLISH_DIR}/conscrypt-openjdk-uber/$VERSION/conscrypt-openjdk-uber-${VERSION}.jar"
TESTJAR="${CONSCRYPT_HOME}/openjdk/build/libs/conscrypt-openjdk-${VERSION}-tests.jar"

if $BUILD_ONLY; then
	echo "Java version:"
	java -version || fail "Cannot run Java."
	echo "Building test jar."
	cd "$CONSCRYPT_HOME"
	./gradlew :conscrypt-openjdk:testJar --console=plain || fail "Gradle build failed."
	test -f "$TESTJAR" || fail "Test jar not built: ${TESTJAR}."
	echo "Test jar built: ${TESTJAR}"
	exit 0
fi


echo "Java version:"
java -version || fail "Cannot run Java."

test -f "$TESTJAR" || fail "Test jar not found: ${TESTJAR}.  Run: $0 --build"
if find "$CONSCRYPT_HOME/common/src/test" \
        "$CONSCRYPT_HOME/openjdk/src/test" \
        -newer "$TESTJAR" -type f | grep -q .; then
    fail "Test jar is out of date (source files changed).  Run: $0 --build"
fi
test -f "$UBERJAR" || fail "Uber jar not found: ${UBERJAR}."

if [ -f "$JUNITJAR" ]; then
	echo "JUnit console runner: ${JUNITJAR}."
else
	echo "Downloading JUnit console runner."
	mvn org.apache.maven.plugins:maven-dependency-plugin:3.8.0:copy \
		-Dartifact=org.junit.platform:junit-platform-console-standalone:1.11.2 \
		-DoutputDirectory="$TMPDIR" \
		-Dmdep.stripVersion=true \
		|| fail "Maven download of junit failed."
fi
test -f "$JUNITJAR" || fail "JUnit not found."

# SIGTERM handler, e.g. for when tests hang and time out.
# Send SIGQUIT to test process to get thread dump, give it
# a few seconds to complete and then kill it.
dump_threads() {
    echo "Generating stack dump."
    ps -fp "$TESTPID"
    kill -QUIT "$TESTPID"
    sleep 3
    kill -KILL "$TESTPID"
    exit 1
}

if [ -n "$TESTS" ]; then
    case "$TESTS" in
        *\#*) TESTSEL="--select-method=${TESTS}" ;;
        *)    TESTSEL="--select-class=${TESTS}" ;;
    esac
    echo "Running test: ${TESTS}."
else
    TESTSEL="--scan-classpath -n=org.conscrypt.ConscryptOpenJdkSuite"
    echo "Running tests."
fi

java $JAVADEBUG $JAVA_OPTS -jar "$JUNITJAR" execute -cp "${UBERJAR}:${TESTJAR}" \
     $TESTSEL --reports-dir=. \
     --fail-if-no-tests $VERBOSE &

case $(uname -s) in
    Darwin|Linux)
        trap dump_threads SIGTERM SIGINT
        ;;
    *)
        # TODO: Probably won't work on Windows but thread dumps
        # work there already.
        ;;
esac

TESTPID=$!
wait "$TESTPID"
