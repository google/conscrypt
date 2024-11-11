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
#

# Allows testing of a locally publish uber jar with against an
# arbitrary Java version using the JUnit console test runner (which
# will be downloaded if not present).
#
# First build and locally publish an uber jar, e.g. using
# publishLocalUber.sh
#
# Second set up the version of Java to be used for testing, e.g. by
# setting JAVA_HOME
#
# Then run this script which will download the JUnit runner if needed,
# build the Conscrypt testJar and then run the tests.
#
# Essentially these are the same steps as the final test matrix in the
# Github CI script.

CONSCRYPT_HOME="${CONSCRYPT_HOME:-$HOME/src/conscrypt}"
BUILD="$CONSCRYPT_HOME/build.gradle"
M2_REPO="${M2_REPO:-$HOME/.m2/repository}"
PUBLISH_DIR="${M2_REPO}/org/conscrypt"
TMPDIR="${TMPDIR:-$HOME/tmp/conscrypt}"
JUNITJAR="$TMPDIR/junit-platform-console-standalone.jar"

die() {
	echo "*** " $@
	exit 1
}

usage() {
	echo "testLocalUber.sh [args]"
	echo ""
	echo "-h, --help     Help"
	echo "-v, --verbose  Verbose test output"
	echo "-d, --debug    Wait for debugger on test startup"
	exit 0
}

while [ "$1" ]; do
	case "$1" in
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
			die "Unknown argument $1 - try --help"
			;;
	esac
	shift
done

mkdir -p "$TMPDIR" || die "Unable to create ${TMPDIR}."

test -f "$BUILD" || die "Conscrypt build.gradle file not found.  Check CONSCRYPT_HOME."
VERSION=$(sed -nE 's/^ *version *= *"(.*)"/\1/p' $BUILD)
test "$VERSION" || die "Unable to figure out Conscrypt version."
echo "Conscrypt version ${VERSION}."

echo "Java version:"
java -version || die "Cannot run Java."

UBERJAR="${PUBLISH_DIR}/conscrypt-openjdk-uber/$VERSION/conscrypt-openjdk-uber-${VERSION}.jar"
TESTJAR="${CONSCRYPT_HOME}/openjdk/build/libs/conscrypt-openjdk-${VERSION}-tests.jar"
test -f "$UBERJAR" || die "Uber jar not found: ${UBERJAR}."


if [ -f "$JUNITJAR" ]; then
	echo "JUnit console runner: ${JUNITJAR}."
else
	echo "Downloading JUnit console runner."
	mvn org.apache.maven.plugins:maven-dependency-plugin:3.8.0:copy \
		-Dartifact=org.junit.platform:junit-platform-console-standalone:1.11.2 \
		-DoutputDirectory="$TMPDIR" \
		-Dmdep.stripVersion=true \
		|| die "Maven download of junit failed."
fi
test -f "$JUNITJAR" || die "JUnit not found."

echo "Building test jar."
cd $CONSCRYPT_HOME
./gradlew :conscrypt-openjdk:testJar --console=plain
test -f "$TESTJAR" || die "Test jar not built."

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

echo "Running tests."
java $JAVADEBUG -jar "$JUNITJAR" execute -cp "${UBERJAR}:${TESTJAR}" \
     -n='org.conscrypt.ConscryptOpenJdkSuite' \
     --scan-classpath --reports-dir=. \
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
