# How to submit a bug report

If you received an error message, please include it and any exceptions.

We commonly need to know what platform you are on:
 * JDK/JRE version (i.e., ```java -version```)
 * Operating system (i.e., ```uname -a```)

# How to contribute

We definitely welcome patches and contributions to Conscrypt! Here are some
guideline and information about how to do so.

## Before getting started

In order to protect both you and ourselves, you will need to sign the
[Contributor License Agreement](https://cla.developers.google.com/clas).

We follow the [Clang Format](http://clang.llvm.org/docs/ClangFormat.html).
There is support in most IDEs.

| IDE | Clang Format Plugin |
| --- | ------------------- |
| Eclipse | [CppStyle](https://marketplace.eclipse.org/content/cppstyle) |
| IntelliJ | [ClangFormatIJ](https://plugins.jetbrains.com/plugin/8396) |

If planning on making a large change, feel free to [create an issue on
GitHub](https://github.com/conscrypt/issues/new) or send an
email to [conscrypt@googlegroups.com](https://groups.google.com/forum/#!forum/conscrypt) to discuss
beforehand.

## Proposing changes

Make sure that `./gradlew check` (`gradlew check` on Windows) completes
successfully without any new warnings (see [Building](BUILDING.md)). Then create a Pull Request
with your changes. When the changes are accepted, they will be merged or cherry-picked by
a Conscrypt developer.

## Source Overview

The high-level modules are __Common__, __Android__, __OpenJDK__, and __Platform__.

### Common

This contains the bulk of the code for both Java and C. This isn't an actual module and builds no
artifacts. Rather, the other modules just point to this directory as source.

### Android

This module provides the `Platform` class for Android and also adds compatibility classes for
supporting various versions of Android. This generates an `aar` library artifact.

### OpenJDK

These modules provide the `Platform` class for non-Android (OpenJDK-based) systems. It also provides
a native library loader supports bundling the shared library with the JAR.

### Platform
This module contains code that is bundled with the Android operating system. The inclusion in the
build is only to ensure that changes to other modules do not accidentally break the Android build.
