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
<font color="red" size="20"><b><u>NOTE:</u></b> This section is under construction! Artifacts have
not yet been published to the public Maven repositories.</font>

#### Download JARs
You can download
[the JARs](http://search.maven.org/#search%7Cga%7C1%7Cg%3A%22org.conscrypt%22%20AND%20v%3A%221.0.1%22)
directly from the Maven repositories.

#### OpenJDK (i.e. non-Android)

##### Maven
Use the [os-maven-plugin](https://github.com/trustin/os-maven-plugin) to add the dependency:

```
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
  <version>0.0.1-SNAPSHOT</version>
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
  compile 'org.conscrypt:conscrypt-jdk:0.0.1-SNAPSHOT:' + osdetector.classifier
}
```

Artifacts are available for the following platforms:

Classifier | Description
---------------- | -----------
windows-x86_64 | Windows distribution
osx-x86_64 | Mac distribution
linux-x86_64 | Used for Linux

How to Build
------------

If you are making changes to Conscrypt, see the [building
instructions](BUILDING.md).

Source Overview
----------------------------

Here's a quick readers' guide to the code to help folks get started. At a high
level there are three distinct modules: __Common__, __Android__ &
__OpenJDK__.

### Common

This contains the bulk of the code. It contains stub classes for platform-specific functions, which
are stripped out of the final JAR.

It also contains all of the native code, but does not build any native artifacts. Instead, the
platform-specific modules will include this source in their builds.

### Android

This module provides the `Platform` class for Android and also adds compatibility classes for
supporting various versions of Android. This generates an `apk` library artifact.

### OpenJDK

This modules provides the `Platform` class for non-Android (OpenJDK-based) systems. It also provides
a native library loader supports bundling the shared library with the JAR.
