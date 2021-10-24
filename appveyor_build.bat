IF %COMPILER%==cygwin (
    @echo on
    SET "PATH=C:\cywin64\bin;c:\cygwin64;%PATH%"
    c:\cygwin64\bin\bash.exe -lc "setup-x86_64.exe -qnNdO -R C:/cygwin64 -l C:/cygwin/var/cache/setup -P openssl -P libssl-devel -P zlib -P zlib-devel -P ninja -P cmake -P gcc -P make -P autoconf && cd ${APPVEYOR_BUILD_FOLDER} && openssl version && cygcheck -c && pwd && git clone --depth 1 --branch main https://github.com/open-quantum-safe/liboqs.git && cd liboqs && mkdir build && cd build && cmake .. -GNinja -DCMAKE_VERBOSE_MAKEFILE=ON -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DCMAKE_INSTALL_PREFIX=${APPVEYOR_BUILD_FOLDER}/oqs -DOQS_BUILD_ONLY_LIB=ON && ninja -v && ninja install && cd ${APPVEYOR_BUILD_FOLDER} && mkdir -p -m 0755 /var/empty && export LIBOQS_INSTALL=`pwd`/oqs && autoreconf && LDFLAGS=\"-Wl,--stack,20000000\" ./configure --without-openssl-header-check --with-liboqs-dir=`pwd`/oqs --with-libs=-lm && make && make install && TEST_SSH_UNSAFE_PERMISSIONS=1 make tests LTESTS=\"\" "
)
