Conscrypt - A Java Security Provider
========================================

Conscrypt is a Java Security Provider (JSP) that implements parts of the
Java Cryptography Extension (JCE) and Java Secure Socket Extension (JSSE).
It uses BoringSSL to provide cryptograhpic primitives and Transport Layer
Security (TLS) for Java applications on Android and OpenJDK.

The core SSL engine has borrowed liberally from the [Netty](http://netty.io/) project and their
work on [netty-tcnative](http://netty.io/wiki/forked-tomcat-native.html), giving `Conscrypt`
similar performance.

<table>
  <tr>
    <td><b>Homepage:</b></td>
    <td>
      <a href="https://conscrypt.org/">conscrypt.org</a>
    </td>
  </tr>
  <tr>
    <td><b>Mailing List:</b></td>
    <td>
      <a href="https://groups.google.com/forum/#!forum/conscrypt">conscrypt@googlegroups.com</a>
    </td>
  </tr>
</table>

Download
-------------
<b><u>NOTE:</u> This section is under construction! Artifacts have
not yet been published to the public Maven repositories.</b>

#### Download JARs
You can download
[the JARs](http://search.maven.org/#search%7Cga%7C1%7Cg%3A%22org.conscrypt%22%20AND%20v%3A%221.1.0%22)
directly from the Maven repositories.

#### OpenJDK (i.e. non-Android)

##### Native Classifiers

The OpenJDK artifacts are platform-dependent, since each embeds a native library for a particular
platform. We publish artifacts to Maven Central for the following platforms:

Classifier | Description
---------------- | -----------
windows-x86_64 | Windows distribution
osx-x86_64 | Mac distribution
linux-x86_64 | Used for Linux

##### Maven

Use the [os-maven-plugin](https://github.com/trustin/os-maven-plugin) to add the dependency:

```xml
<build>
  <extensions>
    <extension>
      <groupId>kr.motd.maven</groupId>
      <artifactId>os-maven-plugin</artifactId>
      <version>1.4.1.Final</version>
    </extension>
  </extensions>
</build>

<dependency>
  <groupId>org.conscrypt</groupId>
  <artifactId>conscrypt-openjdk</artifactId>
  <version>1.1.0-SNAPSHOT</version>
  <classifier>${os.detected.classifier}</classifier>
</dependency>
```

##### Gradle
Use the [osdetector-gradle-plugin](https://github.com/google/osdetector-gradle-plugin)
(which is a wrapper around the os-maven-plugin) to add the dependency:

```gradle
buildscript {
  repositories {
    mavenCentral()
  }
  dependencies {
    classpath 'com.google.gradle:osdetector-gradle-plugin:1.4.0'
  }
}

// Use the osdetector-gradle-plugin
apply plugin: "com.google.osdetector"

dependencies {
  compile 'org.conscrypt:conscrypt-jdk:1.1.0-SNAPSHOT:' + osdetector.classifier
}
```

##### Uber JAR

For convenience, we also publish an Uber JAR to Maven Central that contains the shared
libraries for all of the published platforms. While the overall size of the JAR is
larger than depending on a platform-specific artifact, it greatly simplifies the task of
dependency management for most platforms.

To depend on the uber jar, simply use the `conscrypt-openjdk-uber` artifacts.

###### Maven
```xml
<dependency>
  <groupId>org.conscrypt</groupId>
  <artifactId>conscrypt-openjdk-uber</artifactId>
  <version>1.1.0-SNAPSHOT</version>
</dependency>
```

###### Gradle
```gradle
dependencies {
  compile 'org.conscrypt:conscrypt-jdk-uber:1.1.0-SNAPSHOT'
}
```


How to Build
------------

If you are making changes to Conscrypt, see the [building
instructions](BUILDING.md).

Source Overview
----------------------------

Here's a quick readers' guide to the code to help folks get started. The high-level modules are __Common__, __Android__,
__OpenJDK__, and __Platform__.

### Common

This contains the bulk of the code for both Java and C. This isn't an actual module and builds no
artifacts. Rather, the other modules just point to this directory as source.

### Android

This module provides the `Platform` class for Android and also adds compatibility classes for
supporting various versions of Android. This generates an `aar` library artifact.

### OpenJDK

This modules provides the `Platform` class for non-Android (OpenJDK-based) systems. It also provides
a native library loader supports bundling the shared library with the JAR.

### Platform

This is not an actual module and is not part of the default build. This is used for building
 Conscrypt as an embedded component of the Android platform.