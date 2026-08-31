# How to: Release Conscrypt to Maven Central and GitHub

## One-Time Setup

#### Setup Maven Central

- You need to have an account on [Maven Central](https://central.sonatype.com/),
  and have access to the namespace `org.conscrypt`. It should be listed in
  [https://central.sonatype.com/publishing/namespaces]
  (https://central.sonatype.com/publishing/namespaces). If you don't have access
  to the namespace, contact a Conscrypt maintainer.

#### Setup GPG

- Install GnuPG and [generate your key
  pair](https://www.gnupg.org/documentation/howtos.html).
- [Publish your public key](https://www.gnupg.org/gph/en/manual.html#AEN464)
  to make it visible to the Sonatype servers
  (e.g. `gpg --keyserver pgp.mit.edu --send-key <key ID>`).

## Make a New Release

Create a new bug with the title "Release Conscrypt X.Y.Z", where X.Y.Z is the
version you want to release. See for example b/555033517.

Document all steps you do in that bug.

In this process here we assume that we release from the `master` branch, which
should be the normal case, and makes releases easier. (If you need to create a
patch release, you need to adapt this process yourself.)

#### Sync with GitHub

Make sure that the latest changes in google3 are exported to GitHub. Run:

```
/google/data/ro/teams/copybara/copybara third_party/java/conscrypt/main_src/copy.bara.sky export
```

Make sure that the copybara transformation works. If it doesn't, it is possible
that one of the transformation is out of date, because the code in google3 has
changed. You need to update the transformation in this case.

This will create a commit in the `google3-export` branch, and overwrite previous
commits in that branch. It also tries to create a pull request, but this may
fail due to lack of permissions. This is not a problem, because we can create
the pull request manually. Create a pull request on GitHub, add a reviewer, and
once it is approved, merge it.

#### Commit the new version number

Make a cl that changes the version number in
`third_party/java/conscrypt/main_src/build.gradle` to the next version you want
to release. (For example, from `2.7-SNAPSHOT` to `2.7.0`, see
cl/973727647.) Submit this cl, and then merge it in github, again running
copybara:

```
/google/data/ro/teams/copybara/copybara third_party/java/conscrypt/main_src/copy.bara.sky export
```

and again, create a pull request, add a reviewer, approve it, and merge it.

Now, the CI pipeline on GitHub should run with the new version number.

#### Download the CI-generated repository

Make sure that `/tmp/m2` is empty, and that `~/Downloads/m2repo-uber.zip` does
not exist:

```
rm -rf /tmp/m2/*
rm -rf ~/Downloads/m2repo-uber.zip
```

In the browser (if you are using a Chromebook, then do this in your cloudtop
instance), go to:
[https://github.com/google/conscrypt/actions](https://github.com/google/conscrypt/actions)

and click on your commit. Verify that all jobs pass,
and if some fail, fix them or re-run the failed jobs.

If everything passes, click on the job "uberjar", and open the tab
"Upload maven repository". It will show a artifact link. Click on it to download
the generated repository.

Verify that the download worked by calling:

```
ls ~/Downloads/m2repo*
```

it should show one entry:

```
m2repo-uber.zip
```

#### Generate the signed jar files

Run this script. It will generate the checksums and signatures for all artifacts
and create three zip files, one for each Conscrypt artifact we want to publish.

```
#!/bin/bash

mkdir /tmp/m2
cp ~/Downloads/m2repo-uber.zip /tmp/m2/m2repo-uber.zip

cd /tmp/m2
unzip m2repo-uber.zip

# remove some metadata files that are not needed
rm /tmp/m2/org/conscrypt/conscrypt-android/maven-metadata-local.xml
rm /tmp/m2/org/conscrypt/conscrypt-openjdk/maven-metadata-local.xml
rm /tmp/m2/org/conscrypt/conscrypt-openjdk-uber/maven-metadata-local.xml

# generate checksums and signatures for all artifacts
for f in /tmp/m2/org/conscrypt/*/*/*; do
  echo "Processing $f..."
  md5sum "$f" | cut -d' ' -f1 > "$f.md5"
  sha1sum "$f" | cut -d' ' -f1 > "$f.sha1"
  sha256sum "$f" | cut -d' ' -f1 > "$f.sha256"
  sha512sum "$f" | cut -d' ' -f1 > "$f.sha512"
  gpg --armor --detach-sign "$f"
done

echo "Zipping conscrypt-android.zip ..."
mkdir -p /tmp/m2/conscrypt-android/org/conscrypt/conscrypt-android
cp -r /tmp/m2/org/conscrypt/conscrypt-android /tmp/m2/conscrypt-android/org/conscrypt/
cd /tmp/m2/conscrypt-android
zip -r conscrypt-android.zip org
mv conscrypt-android.zip ..
cd /tmp/m2
rm -rf /tmp/m2/conscrypt-android

echo "Zipping conscrypt-openjdk.zip ..."
mkdir -p /tmp/m2/conscrypt-openjdk/org/conscrypt/conscrypt-openjdk
cp -r /tmp/m2/org/conscrypt/conscrypt-openjdk /tmp/m2/conscrypt-openjdk/org/conscrypt/
cd /tmp/m2/conscrypt-openjdk
zip -r conscrypt-openjdk.zip org
mv conscrypt-openjdk.zip ..
cd /tmp/m2
rm -rf /tmp/m2/conscrypt-openjdk

echo "Zipping conscrypt-openjdk-uber.zip ..."
mkdir -p /tmp/m2/conscrypt-openjdk-uber/org/conscrypt/conscrypt-openjdk-uber
cp -r /tmp/m2/org/conscrypt/conscrypt-openjdk-uber /tmp/m2/conscrypt-openjdk-uber/org/conscrypt/
cd /tmp/m2/conscrypt-openjdk-uber
zip -r conscrypt-openjdk-uber.zip org
mv conscrypt-openjdk-uber.zip ..
cd /tmp/m2
rm -rf /tmp/m2/conscrypt-openjdk-uber

# clean up the temporary directory
rm -rf /tmp/m2/org

echo "Finished creating zip files successfully!"

echo "Listing contents of conscrypt-android.zip:"
unzip -l conscrypt-android.zip

echo "Listing contents of conscrypt-openjdk.zip:"
unzip -l conscrypt-openjdk.zip

echo "Listing contents of conscrypt-openjdk-uber.zip:"
unzip -l conscrypt-openjdk-uber.zip
```

Check that the these zip files contain the expected files. For example, for `conscrypt-openjdk-uber.zip`, you should look like this:

```
Archive:  /tmp/m2/conscrypt-openjdk-uber.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
        0  2026-08-24 13:11   org/
        0  2026-08-24 13:11   org/conscrypt/
        0  2026-08-24 13:11   org/conscrypt/conscrypt-openjdk-uber/
        0  2026-08-24 13:11   org/conscrypt/conscrypt-openjdk-uber/2.7.0/
      228  2026-08-24 13:11   org/conscrypt/conscrypt-openjdk-uber/2.7.0/conscrypt-openjdk-uber-2.7.0-sources.jar.asc
      129  2026-08-24 13:11   org/conscrypt/conscrypt-openjdk-uber/2.7.0/conscrypt-openjdk-uber-2.7.0-sources.jar.sha512
       65  2026-08-24 13:11   org/conscrypt/conscrypt-openjdk-uber/2.7.0/conscrypt-openjdk-uber-2.7.0-sources.jar.sha256
       41  2026-08-24 13:11   org/conscrypt/conscrypt-openjdk-uber/2.7.0/conscrypt-openjdk-uber-2.7.0-sources.jar.sha1
       33  2026-08-24 13:11   org/conscrypt/conscrypt-openjdk-uber/2.7.0/conscrypt-openjdk-uber-2.7.0-sources.jar.md5
      228  2026-08-24 13:11   org/conscrypt/conscrypt-openjdk-uber/2.7.0/conscrypt-openjdk-uber-2.7.0.pom.asc
      129  2026-08-24 13:11   org/conscrypt/conscrypt-openjdk-uber/2.7.0/conscrypt-openjdk-uber-2.7.0.pom.sha512
       65  2026-08-24 13:11   org/conscrypt/conscrypt-openjdk-uber/2.7.0/conscrypt-openjdk-uber-2.7.0.pom.sha256
       41  2026-08-24 13:11   org/conscrypt/conscrypt-openjdk-uber/2.7.0/conscrypt-openjdk-uber-2.7.0.pom.sha1
       33  2026-08-24 13:11   org/conscrypt/conscrypt-openjdk-uber/2.7.0/conscrypt-openjdk-uber-2.7.0.pom.md5
      228  2026-08-24 13:11   org/conscrypt/conscrypt-openjdk-uber/2.7.0/conscrypt-openjdk-uber-2.7.0-javadoc.jar.asc
      129  2026-08-24 13:11   org/conscrypt/conscrypt-openjdk-uber/2.7.0/conscrypt-openjdk-uber-2.7.0-javadoc.jar.sha512
       65  2026-08-24 13:11   org/conscrypt/conscrypt-openjdk-uber/2.7.0/conscrypt-openjdk-uber-2.7.0-javadoc.jar.sha256
       41  2026-08-24 13:11   org/conscrypt/conscrypt-openjdk-uber/2.7.0/conscrypt-openjdk-uber-2.7.0-javadoc.jar.sha1
       33  2026-08-24 13:11   org/conscrypt/conscrypt-openjdk-uber/2.7.0/conscrypt-openjdk-uber-2.7.0-javadoc.jar.md5
      228  2026-08-24 13:11   org/conscrypt/conscrypt-openjdk-uber/2.7.0/conscrypt-openjdk-uber-2.7.0.jar.asc
      129  2026-08-24 13:11   org/conscrypt/conscrypt-openjdk-uber/2.7.0/conscrypt-openjdk-uber-2.7.0.jar.sha512
       65  2026-08-24 13:11   org/conscrypt/conscrypt-openjdk-uber/2.7.0/conscrypt-openjdk-uber-2.7.0.jar.sha256
       41  2026-08-24 13:11   org/conscrypt/conscrypt-openjdk-uber/2.7.0/conscrypt-openjdk-uber-2.7.0.jar.sha1
       33  2026-08-24 13:11   org/conscrypt/conscrypt-openjdk-uber/2.7.0/conscrypt-openjdk-uber-2.7.0.jar.md5
     1269  2026-08-24 13:11   org/conscrypt/conscrypt-openjdk-uber/2.7.0/conscrypt-openjdk-uber-2.7.0.pom
  6846924  2026-08-24 13:11   org/conscrypt/conscrypt-openjdk-uber/2.7.0/conscrypt-openjdk-uber-2.7.0.jar
   421660  2026-08-24 13:11   org/conscrypt/conscrypt-openjdk-uber/2.7.0/conscrypt-openjdk-uber-2.7.0-sources.jar
    39203  2026-08-24 13:11   org/conscrypt/conscrypt-openjdk-uber/2.7.0/conscrypt-openjdk-uber-2.7.0-javadoc.jar
---------                     -------
  7311040                     28 files
```

#### Upload to Maven Central

Now, we can upload these zip files to Maven Central. Open
https://central.sonatype.com/ in a browser, and log in.

click on "Publish", and then "Publish Component".

You get a form. For "Deployment Name", we write "conscrypt-openjdk-uber version
2.7.0". As description, we also just use "conscrypt-openjdk-uber version
2.7.0". Then click on "Choose File".
Choose "/tmp/m2/conscrypt-openjdk-uber.zip".

Then, you get a pop-up and you have to say that you only share public data.

After the upload finished, click on "Publish Component".

Do the same steps for the other zip files.

It first shows "validating", and a minute later as "validated". Then, you can
click on it, and then click on "Publish". Confirm the terms and again click
"Publish".

It then shows up as "publishing". A bit later, it will show up as "published".

Do this for all three components.

#### Create the release tag on GitHub

Finally, create the release tag on GitHub.

Go to
https://github.com/google/conscrypt/releases/new

"Select Tag", "Create new Tag". Write the tag name, for example, "2.7.0".

Add a description. Check "Pre-release" if it is a "-alpha" release, and click
the button to make the release.

Github will create a new tag, such as:
https://github.com/google/conscrypt/releases/tag/2.7.0.

#### Submit a commit with the next version number

Now, you should change the version number in `build.gradle` back to a snapshot
version, with the `-SNAPSHOT` suffix. For example, from `2.7.0` to
`2.7-SNAPSHOT`.

#### Update the documentation

Update the documentation to reflect the new release. For example, the
[README](https://github.com/google/conscrypt/blob/master/README.md).
