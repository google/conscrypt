REM Release automation script for Windows builds.  This should be run
REM after the Linux build has created the staging repository and
REM selected the BoringSSL revision.  Must be run from the top-level
REM conscrypt directory, which should be synced to the appropriate
REM release branch.

@echo off
setlocal

if "%2"=="" (
    echo Usage: %0 ^<boringssl revision^> ^<repository ID^>
    exit /B
)

REM TODO(flooey): The BoringSSL directory needs to be at ../boringssl
pushd ..\boringssl

if "%JAVA_HOME%"=="" (
    for /F "usebackq delims==" %%i in (`where java`) do set JAVA_HOME=%%~dpi
)
set JAVA_HOME=%JAVA_HOME:\bin\=%

if "%BORINGSSL_HOME%"=="" (set BORINGSSL_HOME=%cd%)

git checkout master
git pull
git checkout %1

pushd .
call "C:\Program Files (x86)\Microsoft Visual Studio\2017\Community\VC\Auxiliary\Build\vcvarsall.bat" x86
popd
cd build32
ninja
cd ..

pushd .
call "C:\Program Files (x86)\Microsoft Visual Studio\2017\Community\VC\Auxiliary\Build\vcvarsall.bat" x86_amd64
popd
cd build64
ninja

popd

call gradlew conscrypt-openjdk:build
call gradlew conscrypt-openjdk:publish -Dorg.gradle.parallel=false -PrepositoryId=%2
