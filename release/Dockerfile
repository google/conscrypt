FROM centos:7

RUN yum install -y git \
                   tar \
                   wget \
                   which \
                   make \
                   emacs \
                   autoconf \
                   curl-devel \
                   unzip \
                   automake \
                   libtool \
                   glibc-static.i686 \
                   glibc-devel \
                   glibc-devel.i686

RUN yum update -y nss

# Install Java 8
RUN wget -q --no-cookies --no-check-certificate \
    --header "Cookie: gpw_e24=http%3A%2F%2Fwww.oracle.com%2F; oraclelicense=accept-securebackup-cookie" \
    "http://download.oracle.com/otn-pub/java/jdk/8u131-b11/d54c1d3a095b4ff2b6607d096fa80163/jdk-8u131-linux-x64.tar.gz" \
    -O - | tar xz -C /var/local
ENV JAVA_HOME /var/local/jdk1.8.0_131
ENV PATH $JAVA_HOME/bin:$PATH

# Install Clang 5
RUN yum install -y centos-release-scl
RUN yum install -y llvm-toolset-7
ENV CC /opt/rh/llvm-toolset-7/root/usr/bin/clang
ENV CXX /opt/rh/llvm-toolset-7/root/usr/bin/clang++

# Download and install Golang
WORKDIR /
ENV GOLANG_VERSION 1.10.5
ENV GOLANG_DOWNLOAD_URL https://golang.org/dl/go$GOLANG_VERSION.linux-amd64.tar.gz
ENV GOLANG_DOWNLOAD_SHA256 a035d9beda8341b645d3f45a1b620cf2d8fb0c5eb409be36b389c0fd384ecc3a
RUN curl -fsSL "$GOLANG_DOWNLOAD_URL" -o golang.tar.gz \
	&& echo "$GOLANG_DOWNLOAD_SHA256  golang.tar.gz" | sha256sum -c - \
	&& tar -C /usr/local -xzf golang.tar.gz \
	&& rm golang.tar.gz
ENV GOPATH /go
ENV PATH $GOPATH/bin:/usr/local/go/bin:$PATH
RUN mkdir -p "$GOPATH/src" "$GOPATH/bin" && chmod -R 777 "$GOPATH"

# Build and install CMake from source.
WORKDIR /usr/src
RUN git clone git://cmake.org/cmake.git CMake && \
  cd CMake && \
  git checkout v3.4.1 && \
  mkdir /usr/src/CMake-build && \
  cd /usr/src/CMake-build && \
  /usr/src/CMake/bootstrap \
    --parallel=$(grep -c processor /proc/cpuinfo) \
    --prefix=/usr && \
  make -j$(grep -c processor /proc/cpuinfo) && \
  ./bin/cmake \
    -DCMAKE_BUILD_TYPE:STRING=Release \
    -DCMAKE_USE_OPENSSL:BOOL=ON . && \
  make install && \
  cd .. && rm -rf CMake*

# Build and install Python from source.
WORKDIR /usr/src
ENV PYTHON_VERSION 2.7.14
RUN wget https://www.python.org/ftp/python/${PYTHON_VERSION}/Python-${PYTHON_VERSION}.tgz && \
  tar xvzf Python-${PYTHON_VERSION}.tgz && \
  cd Python-${PYTHON_VERSION} && \
  ./configure && \
  make -j$(grep -c processor /proc/cpuinfo) && \
  make install && \
  cd .. && rm -rf Python-${PYTHON_VERSION}*

# Build and install ninja from source.
WORKDIR /usr/src
ENV NINJA_VERSION 1.8.2
RUN git clone https://github.com/martine/ninja.git && \
  cd ninja && \
  git checkout v$NINJA_VERSION && \
  ./configure.py --bootstrap && \
  mv ninja /usr/bin/ && \
  cd .. && rm -rf ninja

# Build and install BoringSSL from source.
ENV BORINGSSL_HOME /usr/src/boringssl
ENV BORINGSSL_BUILD_DIR $BORINGSSL_HOME/build64
RUN git clone --depth 1 https://boringssl.googlesource.com/boringssl $BORINGSSL_HOME
RUN mkdir $BORINGSSL_BUILD_DIR
WORKDIR $BORINGSSL_BUILD_DIR
RUN cmake -DCMAKE_POSITION_INDEPENDENT_CODE=TRUE -DCMAKE_BUILD_TYPE=Release -DCMAKE_ASM_FLAGS=-Wa,--noexecstack -GNinja ..
RUN ninja

# Download conscrypt.
WORKDIR /
RUN git clone --depth 1 --no-single-branch https://github.com/google/conscrypt.git

# Start in toolset environment that uses Clang 5
CMD ["scl", "enable", "llvm-toolset-7", "bash"]
