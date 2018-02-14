FROM centos:6.6

# This enables compatibility with Docker overlayfs
RUN yum install -y yum-plugin-ovl

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

# Install clang.
RUN yum install -y epel-release
RUN yum install -y clang

# Install Java 8
RUN wget -q --no-cookies --no-check-certificate \
    --header "Cookie: gpw_e24=http%3A%2F%2Fwww.oracle.com%2F; oraclelicense=accept-securebackup-cookie" \
    "http://download.oracle.com/otn-pub/java/jdk/8u131-b11/d54c1d3a095b4ff2b6607d096fa80163/jdk-8u131-linux-x64.tar.gz" \
    -O - | tar xz -C /var/local
ENV JAVA_HOME /var/local/jdk1.8.0_131
ENV PATH $JAVA_HOME/bin:$PATH

# Install GCC 4.8
# We'll get and "Rpmdb checksum is invalid: dCDPT(pkg checksums)" error caused by
# docker issue when using overlay storage driver, but all the stuff we need
# will be installed, so for now we just ignore the error.
WORKDIR /etc/yum.repos.d
RUN wget --no-check-certificate http://people.centos.org/tru/devtools-2/devtools-2.repo
RUN yum install -y devtoolset-2-gcc \
                   devtoolset-2-binutils \
                   devtoolset-2-gcc-c++ \
                   || true
ENV CC /opt/rh/devtoolset-2/root/usr/bin/gcc
ENV CXX /opt/rh/devtoolset-2/root/usr/bin/g++

# Download and install Golang
WORKDIR /
ENV GOLANG_VERSION 1.6.4
ENV GOLANG_DOWNLOAD_URL https://golang.org/dl/go$GOLANG_VERSION.linux-amd64.tar.gz
ENV GOLANG_DOWNLOAD_SHA256 b58bf5cede40b21812dfa031258db18fc39746cc0972bc26dae0393acc377aaf
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
ENV PYTHON_VERSION 2.7.10
RUN wget https://www.python.org/ftp/python/${PYTHON_VERSION}/Python-${PYTHON_VERSION}.tgz && \
  tar xvzf Python-${PYTHON_VERSION}.tgz && \
  cd Python-${PYTHON_VERSION} && \
  ./configure && \
  make -j$(grep -c processor /proc/cpuinfo) && \
  make install && \
  cd .. && rm -rf Python-${PYTHON_VERSION}*

# Build and install ninja from source.
WORKDIR /usr/src
ENV NINJA_VERSION 1.6.0
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
RUN git clone --depth 1 https://github.com/google/conscrypt.git

# Start in devtoolset environment that uses GCC 4.8
CMD ["scl", "enable", "devtoolset-2", "bash"]
