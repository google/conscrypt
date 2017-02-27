How to Create a Release of Conscrypt (for Maintainers Only)
===========================================================

Build Environments
------------------
We deploy Conscrypt to Maven Central under the following systems:
- Ubuntu 14.04 with Docker 1.6.1 that runs CentOS 6.6
- Windows 7 64-bit
- Mac OS X 10.7+

Other systems may also work, but we haven't verified them.

BoringSSL Version
-----------------

Each build environment for a particular release *MUST* use the same version
of BoringSSL. This is necessary in order to maintain consistency across
platforms as well as to allow the Uber JAR to specify a single version for
BoringSSL in its MANIFEST.MF.

When deploying, it may be useful to begin with Linux (via Docker),
taking note of the BoringSSL version used, and then deploying
Mac and Windows with that version via:

```bash
boringssl$ git checkout <commit id>
```

Prerequisites
-------------

### Setup OSSRH and Signing

If you haven't deployed artifacts to Maven Central before, you need to setup
your OSSRH (OSS Repository Hosting) account and signing keys.
- Follow the instructions on [this
  page](http://central.sonatype.org/pages/ossrh-guide.html) to set up an
  account with OSSRH.
  - You only need to create the account, not set up a new project
  - Contact a Conscrypt maintainer to add your account after you have created it.
- (For release deployment only) Install GnuPG and [generate your key
  pair](https://www.gnupg.org/documentation/howtos.html). You'll also
  need to [publish your public key](https://www.gnupg.org/gph/en/manual.html#AEN464)
  to make it visible to the Sonatype servers
  (e.g. `gpg --keyserver pgp.mit.edu --send-key <key ID>`).
- Put your GnuPG key password and OSSRH account information in
  `<your-home-directory>/.gradle/gradle.properties`.

```
# You need the signing properties only if you are making release deployment
signing.keyId=<8-character-public-key-id>
signing.password=<key-password>
signing.secretKeyRingFile=<your-home-directory>/.gnupg/secring.gpg

ossrhUsername=<ossrh-username>
ossrhPassword=<ossrh-password>
checkstyle.ignoreFailures=false
```

Tagging the Release
----------------------
The first step in the release process is to create a release branch, bump
versions, and create a tag for the release. Our release branches follow the naming
convention of `v<major>.<minor>.x`, while the tags include the patch version
`v<major>.<minor>.<patch>`. For example, the same branch `v1.0.x`
would be used to create all `v1.0` tags (e.g. `v1.0.0`, `v1.0.1`).

1. Create the release branch and push it to GitHub:

   ```bash
   $ git checkout -b 1.0.x master
   $ git push upstream 1.0.x
   ```
2. Update `master` branch to the next minor snapshot (e.g. `1.1.0-SNAPSHOT`)
   and update references to the version in `README.md`.

   ```bash
   $ git checkout -b bump-version master
   # Change version to next minor (and keep -SNAPSHOT)
   $ ${EDITOR:-nano -w} build.gradle
   # Bump documented versions.
   $ ${EDITOR:-nano -w} README.md
   $ ./gradlew build
   $ git commit -a -m "Start 1.1.0 development cycle"
   ```
3. Go through PR review and push the master branch to GitHub:

   ```bash
   $ git checkout master
   $ git merge --ff-only bump-version
   $ git push upstream master
   ```
4. In the release branch, remove "-SNAPSHOT" for the next release version
   (e.g. '1.0.0') and update references to the version in `README.md`.
   Commit the result and make a tag:

   ```bash
   $ git checkout 1.0.x
   # Change version to remove -SNAPSHOT
   $ ${EDITOR:-nano -w} build.gradle
   # Bump documented versions.
   $ ${EDITOR:-nano -w} README.md
   $ git commit -a -m "Change version to 1.0.0"
   $ git tag -a 1.0.0 -m "Version 1.0.0"
   ```
5. In the release branch, bump to the next patch snapshot version
   (e.g. `1.0.1-SNAPSHOT`). Commit the result:

   ```bash
   # Change version to next patch and add -SNAPSHOT
   $ ${EDITOR:-nano -w} build.gradle
   $ ./gradlew build
   $ git commit -a -m "Bump version to 1.0.1-SNAPSHOT"
   ```
7. Go through PR review and push the release tag and updated release branch to
   GitHub:

   ```bash
   $ git push upstream 1.0.0
   $ git push upstream 1.0.x
   ```

Setup Build Environment
---------------------------

### Linux
The deployment for Linux uses [Docker](https://www.docker.com/) running
CentOS 6.6 in order to ensure that we have a consistent deployment environment
on Linux. You'll first need to install Docker if not already installed on your
system.

1. From the conscrypt source directory:

   ```bash
   conscrypt$ docker build -t conscrypt-deploy .
   ```
2. Start a Docker container that has the deploy environment set up for you. The
   Conscrypt source is cloned into `/conscrypt`.

   ```bash
   $ docker run -it --rm=true conscrypt-deploy
   ```

   Note that the container will be deleted after you exit. Any changes you have
   made (e.g., copied configuration files) will be lost. If you want to keep the
   container, remove `--rm=true` from the command line.
3. Next, you'll need to copy your OSSRH credentials and GnuPG keys to your docker container.
   In Docker:
   ```
   # mkdir /root/.gradle
   ```
   Find the container ID in your bash prompt, which is shown as `[root@<container-ID> ...]`.
   In host:
   ```
   $ docker cp ~/.gnupg <container-ID>:/root/
   $ docker cp ~/.gradle/gradle.properties <container-ID>:/root/.gradle/
   ```

   You'll also need to update `signing.secretKeyRingFile` in
   `/root/.gradle/gradle.properties` to point to `/root/.gnupg/secring.gpg`.

### Windows and Mac

For Windows and Mac, see [BUILDING](BUILDING.md) for instructions for setting up the build environment.

Build and Deploy
----------------
We currently distribute the following OSes and architectures:

| OS | x86_32 | x86_64 |
| --- | --- | --- |
| Linux |  | X |
| Windows | X | X |
| Mac |  | X |

Deployment to Maven Central (or the snapshot repo) is a two-step process. The only
artifact that is platform-specific is codegen, so we only need to deploy the other
jars once. So the first deployment is for all of the artifacts from one of the selected
OS/architectures. After that, we then deploy the codegen artifacts for the remaining
OS/architectures.

**NOTE: _Before building/deploying, be sure to switch to the appropriate branch or tag in
the Conscrypt source directory._**

### First Deployment (or SNAPSHOT)

As stated above, this only needs to be done once for one of the selected OS/architectures.
The following command will build the whole project and upload it to Maven
Central. Parallel building [is not safe during
uploadArchives](https://issues.gradle.org/browse/GRADLE-3420).
```bash
conscrypt$ ./gradlew build && ./gradlew -Dorg.gradle.parallel=false uploadArchives
```

If the version has the `-SNAPSHOT` suffix, the artifacts will automatically
go to the snapshot repository. Otherwise it's a release deployment and the
artifacts will go to a freshly created staging repository.

### Deploy Additional Platforms (Release Deployment Only)
The previous step will only deploy the artifacts for the OS you run on
it and the architecture of your JVM. For a fully fledged deployment, you will
need to deploy for each supported OS/architecture.

To deploy the codegen for an OS and architecture, you must run the following
commands on that OS and specify the architecture by the flag `-PtargetArch=<arch>`.

When deploying a Release, the first deployment will create
[a new staging repository](https://oss.sonatype.org/#stagingRepositories). You'll need
to look up the ID in the OSSRH UI (usually in the form of `orgconscrypt-*`). Codegen
deployment commands should include `-PrepositoryId=<repository-id>` in order to
ensure that the artifacts are pushed to the same staging repository.

```bash
conscrypt$ ./gradlew build uploadArchives -PtargetArch=<arch> \
    -PrepositoryId=<repository-id> -Dorg.gradle.parallel=false
```

Now finish [Releasing on Maven Central](#releasing-on-maven-central).

### Deploy the Uber JAR (Release Deployment Only)
Once all of the native JARs appear on Maven Central, you can build and deploy
the Uber JAR that contains all of them.

```bash
conscrypt$ ./gradlew conscrypt-openjdk-uber:build \
           -Dorg.conscrypt.openjdk.buildUberJar=true

conscrypt$ ./gradlew conscrypt-openjdk-uber:uploadArchives \
           -Dorg.gradle.parallel=false \
           -Dorg.conscrypt.openjdk.buildUberJar=true
```

This will create
[a new staging repository](https://oss.sonatype.org/#stagingRepositories),
so you'll need to [close and release](#releasing-on-maven-central) the
repository via the OSSRH UI, as you did in the previous step.

Releasing on Maven Central
--------------------------
Once all of the artifacts have been pushed to the staging repository, the
repository must first be `closed`, which will trigger several sanity checks
on the repository. If this completes successfully, the repository can then
be `released`, which will begin the process of pushing the new artifacts to
Maven Central (the staging repository will be destroyed in the process). You can
see the complete process for releasing to Maven Central on the [OSSRH site]
(http://central.sonatype.org/pages/releasing-the-deployment.html).

Notify the Community
--------------------
Finally, document and publicize the release.

1. Add [Release Notes](https://github.com/google/conscrypt/releases) for the new tag.
   The description should include any major fixes or features since the last release.
   You may choose to add links to bugs, PRs, or commits if appropriate.
2. Post a release announcement to [conscrypt](https://groups.google.com/forum/#!forum/conscrypt)
   (`conscrypt@googlegroups.com`). The title should be something that clearly identifies
   the release (e.g.`Conscrypt <tag> Released`).
