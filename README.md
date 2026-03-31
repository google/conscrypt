# Evolving Conscrypt's Open Source Approach

Hello Conscrypt Developers,

We're refining our **open source strategy for Conscrypt** to ensure its long-term health and sustainability. To optimize our development efforts and focus resources, we are making some changes to how Conscrypt is developed and how we handle contributions. The primary development of Conscrypt will now be done internally at Google. While we value community input, we will no longer be able to accept external contributions in the form of pull requests on the GitHub repository. This change allows us to better allocate resources to core development and ensure the project's long-term sustainability. To ensure transparency and continued access for the community, we will:

*   **Continue Mirroring to GitHub:** All internal changes will be regularly mirrored to the public GitHub repository. Note that mirroring to GitHub might be paused for a short period of time during the transition to internal development.
*   **Maintain Bug Reporting Channels:** Please keep reporting bugs through GitHub Issues. For Android-specific bugs, the Android Issue Tracker is the place to go: [Report Bugs](https://source.android.com/docs/setup/contribute/report-bugs).

### What’s staying the same

The platform version of Conscrypt receives regular updates, including the latest features and security patches, through the Google Play system updates program (Project Mainline). This means that even devices running older Android versions can benefit from the most recent Conscrypt improvements without requiring a full OS update.

### What’s changing

As part of this shift, we will no longer be able to accept external pull requests on GitHub.

### What do you need to do

*   Immediately, nothing.
*   For Android developers, we recommend leveraging the Conscrypt version built into the Android platform, which is also the default provider.

We appreciate the Conscrypt community and look forward to continuing to offer a secure and efficient security provider.

## Guidance for Android App Developers:

Most Android devices include Conscrypt as a core part of the platform's security providers. The Java Cryptography Architecture (JCA) framework allows for multiple security providers, and the system selects one when you request a cryptographic algorithm implementation (like Cipher, SSLContext, MessageDigest, etc.).

### Using the Platform Version (Recommended):

To use the platform-provided Conscrypt, you generally don't need to do anything specific. When requesting an algorithm, omit the provider name. The Android system will automatically select the highest-priority provider that offers the requested algorithm, which is typically the built-in Conscrypt.

*Example (Java):*

```java
import javax.net.ssl.SSLContext;
import java.security.Security;
import java.security.Provider;

try {
    // Get an SSLContext instance using the default highest-priority provider
    SSLContext sslContext = SSLContext.getInstance("TLS");
    // Initialize and use sslContext

    // Example: Listing providers to see what's available
    // Provider[] providers = Security.getProviders();
    // for (Provider provider : providers) {
    //     System.out.println("Provider: " + provider.getName());
    // }
} catch (NoSuchAlgorithmException e) {
    // Handle exception
    e.printStackTrace();
}
```

*Example (Kotlin):*

```kotlin
import javax.net.ssl.SSLContext
import java.security.Security
import java.security.Provider

try {
    // Get an SSLContext instance using the default highest-priority provider
    val sslContext = SSLContext.getInstance("TLS")
    // Initialize and use sslContext

    // Example: Listing providers to see what's available
    // val providers = Security.getProviders()
    // providers.forEach { provider ->
    //     println("Provider: ${provider.name}")
    // }
} catch (e: NoSuchAlgorithmException) {
    // Handle exception
    e.printStackTrace()
}
```

By *not* specifying a provider name in getInstance() calls, you rely on the Android system's default provider order, ensuring you use the up-to-date and maintained version of Conscrypt that is part of the Android platform.

Conscrypt - A Java Security Provider
========================================

Conscrypt is a Java Security Provider (JSP) that implements parts of the Java
Cryptography Extension (JCE) and Java Secure Socket Extension (JSSE).  It uses
BoringSSL to provide cryptographic primitives and Transport Layer Security (TLS)
for Java applications on Android and OpenJDK.  See [the capabilities
documentation](CAPABILITIES.md) for detailed information on what is provided.

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
Conscrypt supports **Java 8** or later on OpenJDK and **KitKat (API Level
19)** or later on Android.  The build artifacts are available on Maven Central.

### Download JARs
You can download
[the JARs](http://search.maven.org/#search%7Cga%7C1%7Cg:%22org.conscrypt%22)
directly from the Maven repositories.

### OpenJDK (i.e. non-Android)

#### Native Classifiers

The OpenJDK artifacts are platform-dependent since each embeds a native library for a particular
platform. We publish artifacts to Maven Central for the following platforms:

Classifier | OS | Architecture
-----------| ------- | ---------------- |
linux-x86_64 | Linux | x86_64 (64-bit)
osx-x86_64 | Mac | x86_64 (64-bit)
windows-x86 | Windows | x86 (32-bit)
windows-x86_64 | Windows | x86_64 (64-bit)

#### Maven

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
  <version>2.5.2</version>
  <classifier>${os.detected.classifier}</classifier>
</dependency>
```

#### Gradle
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
  compile 'org.conscrypt:conscrypt-openjdk:2.5.2:' + osdetector.classifier
}
```

#### Uber JAR

For convenience, we also publish an Uber JAR to Maven Central that contains the shared
libraries for all of the published platforms. While the overall size of the JAR is
larger than depending on a platform-specific artifact, it greatly simplifies the task of
dependency management for most platforms.

To depend on the uber jar, simply use the `conscrypt-openjdk-uber` artifacts.

##### Maven
```xml
<dependency>
  <groupId>org.conscrypt</groupId>
  <artifactId>conscrypt-openjdk-uber</artifactId>
  <version>2.5.2</version>
</dependency>
```

##### Gradle
```gradle
dependencies {
  compile 'org.conscrypt:conscrypt-openjdk-uber:2.5.2'
}
```

### Android

The Android AAR file contains native libraries for x86, x86_64, armeabi-v7a, and
arm64-v8a.

#### Gradle

```gradle
dependencies {
  implementation 'org.conscrypt:conscrypt-android:2.5.2'
}
```


How to Build
------------

If you are making changes to Conscrypt, see the [building
instructions](BUILDING.md).
