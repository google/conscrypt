How to Create a Conscrypt Release
====================================

One-Time Setup
--------------

These steps need to be performed once by each person doing releases.

### Platforms

Conscrypt is built on Linux, Mac, and Windows, so ensure you have access to machines
running all three.  The 1.0.0 release was made with the following configuration:

* Ubuntu 14.04
* MacOS Sierra (10.12)
* Windows Server 2016

### Software

The following software is necessary and may not be installed by default:

<!-- TODO(flooey): Expand and link these, there's probably more -->
* Linux: [Docker](https://www.docker.com/), [Android SDK](https://developer.android.com/studio/index.html)
* MacOS: Java SDK
* Windows: MSVC, git, NASM, Java

### Setup OSSRH and GPG

If you haven't deployed artifacts to Maven Central before, you need to setup
your OSSRH (OSS Repository Hosting) account and signing keys.
- Follow the instructions on [this
  page](http://central.sonatype.org/pages/ossrh-guide.html) to set up an
  account with OSSRH.
  - You only need to create the account, not set up a new project
  - Contact a Conscrypt maintainer to add your account after you have created it.
- Install GnuPG and [generate your key
  pair](https://www.gnupg.org/documentation/howtos.html).
- [Publish your public key](https://www.gnupg.org/gph/en/manual.html#AEN464)
  to make it visible to the Sonatype servers
  (e.g. `gpg --keyserver pgp.mit.edu --send-key <key ID>`).

### Get the signing certificates

Contact an existing Conscrypt maintainer to get the keystore containing the
code signing certificate.

### Set up gradle.properties

Add your OSSRH credentials, GPG key information, and the code signing keystore details
to `$HOME/.gradle/gradle.properties`.

```
signing.keyId=<8-character-public-key-id>
signing.password=<key-password>
signing.secretKeyRingFile=<your-home-directory>/.gnupg/secring.gpg

signingKeystore=<path-to-keystore>
signingPassword=<keystore-password>

ossrhUsername=<ossrh-username>
ossrhPassword=<ossrh-password>
checkstyle.ignoreFailures=false
```

Once Per Release Series Setup
-----------------------------

These steps need to be performed once per `X.Y` release series.

### Create the release branch

We use a branch named `<major>.<minor>.x` for all releases in a series.

Create the branch and push it to GitHub:

```bash
$ git checkout -b 1.0.x master
$ git push upstream 1.0.x
```

### Set the branch protection settings

In the GitHub UI, go to Settings -> Branches and mark the new branch as
protected, with administrators included and restrict pushes to administrators.

### Update the master version

Update the master branch's version to the next minor snapshot.

```bash
$ git checkout -b bump-version master
# Change version in build.gradle to X.Y+1-SNAPSHOT
$ git commit -a -m 'Start X.Y+1 development cycle'
# Push to GitHub and get reviewed like normal
```

Making a New Release
--------------------

### Cherry-pick changes from the master branch (optional)

Cherry-pick any desired master changes since the branch was created.

```bash
$ git checkout 1.0.x
$ git cherry-pick <revision>
```

### Tag the release

```bash
# Change version in build.gradle to this version's number
$ git commit -a -m 'Preparing version 1.0.0'
$ git tag -a 1.0.0 -m 'Version 1.0.0'
```

### Push to GitHub

Push both the branch and the new tag to GitHub.

```bash
$ git push upstream 1.0.x
$ git push upstream 1.0.0
```

### Build the Linux OpenJDK Release

The deployment for Linux uses [Docker](https://www.docker.com/) running
CentOS 6.6 in order to ensure that we have a consistent deployment environment
on Linux.

1. From the conscrypt source directory:

   ```bash
   $ docker build -t conscrypt-deploy release
   ```
1. Start a Docker container that has the deploy environment set up for you. The
   Conscrypt source is cloned into `/conscrypt`.

   ```bash
   $ docker run -it --rm=true conscrypt-deploy
   ```

   Note that the container will be deleted after you exit. Any changes you have
   made (e.g., copied configuration files) will be lost. If you want to keep the
   container, remove `--rm=true` from the command line.
1. Copy your OSSRH credentials and GnuPG keys to your docker container. In Docker:
   ```
   # mkdir /root/.gradle
   ```
   Find the container ID in your bash prompt, which is shown as `[root@<container-ID> ...]`.
   In host:
   ```
   $ docker cp ~/.gnupg <container-ID>:/root/
   $ docker cp ~/.gradle/gradle.properties <container-ID>:/root/.gradle/
   $ docker cp <path to cert keystore> <container-ID>:/root/certkeystore
   ```

   You'll also need to update `signing.secretKeyRingFile` and `signingKeystore` in
   `/root/.gradle/gradle.properties` to point to `/root/.gnupg/secring.gpg` and
   `/root/certkeystore`, respectively.
1. Create the initial build
   ```bash
   $ git checkout 1.0.x
   $ ./gradlew conscrypt-openjdk:build
   $ ./gradlew -Dorg.gradle.parallel=false publish
   ```
1. Note the BoringSSL commit used for this build.
   ```bash
   $ cd /usr/src/boringssl
   $ git log -n 1
   ```
1. Go to the OSSRH UI and note the ID of the new staging repository.  It should be in the 
   form of `orgconscrypt-NNNN`.

### Build the Mac and Windows OpenJDK Releases

See [BUILDING](../BUILDING.md) for instructions for setting up the build environment.

1. Ensure BoringSSL is synced to the same revision as for the Linux build.
   ```bash
   $ git checkout <revision>
   $ cd build64
   $ ninja
   # For Windows only
   $ cd ..\build32
   $ ninja
   ```
1. Build the code and upload it to the staging repository noted previously.
   ```bash
   $ ./gradlew conscrypt-openjdk:build
   $ ./gradlew conscrypt-openjdk:publish -Dorg.gradle.parallel=false -PrepositoryId=<repository-id>
   ```
   (Omit the `./` for the Windows build.)

### Close and Release the Staging Repository

1. Navigate to the staging repository, open the contents, and ensure there are jars for
   each supported build environment: linux-x86_64, osx-x86_64, windows-x86, and windows-x86_64.
1. Click the `close` button at the top of the staging repo list.
1. After the automated checks are done, click the `release` button at the top of the staging repo list.

You can see the complete process for releasing to Maven Central on the [OSSRH site]
(http://central.sonatype.org/pages/releasing-the-deployment.html).

It will take several hours for the jars to show up on [Maven Central](http://search.maven.org).

### Build the Android Release

The Android build is not yet integrated into the Docker container, so on any machine with
the Android SDK installed, do the following:

1. Build the code.
   ```bash
   $ ./gradlew conscrypt-android:build
   $ ./gradlew conscrypt-android:publish -Dorg.gradle.parallel=false
   ```
1. Visit the OSSRH site and close and release the repository.

### Build the Uber Jar

Once the platform-specific jars have shown up on Maven Central, return to the Docker container
and build the Uber jar.

1. Build the code.
   ```bash
   # If you left the container, reattach to it
   $ docker container attach {CONTAINER_ID}
   $ ./gradlew conscrypt-openjdk-uber:build -Dorg.conscrypt.openjdk.buildUberJar=true
   $ ./gradlew conscrypt-openjdk-uber:publish -Dorg.gradle.parallel=false -Dorg.conscrypt.openjdk.buildUberJar=true
   ```
1. Visit the OSSRH site and close and release the repository.

### Notify the Community

Finally, document and publicize the release.

1. Add [Release Notes](https://github.com/google/conscrypt/releases) for the new tag.
   The description should include any major fixes or features since the last release.
   You may choose to add links to bugs, PRs, or commits if appropriate.
2. Post a release announcement to [conscrypt](https://groups.google.com/forum/#!forum/conscrypt)
   (`conscrypt@googlegroups.com`). The title should be something that clearly identifies
   the release (e.g.`Conscrypt <tag> Released`).
