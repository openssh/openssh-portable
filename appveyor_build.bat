IF %COMPILER%==cygwin (
    @echo on
    SET "PATH=C:\cywin64\bin;c:\cygwin64;%PATH%"
    c:\cygwin64\bin\bash.exe -lc "export PPD=$OLDPWD && export LIBOQS_INSTALL=$PPD/oqs && env && pwd && setup-x86_64.exe -qnNdO -R C:/cygwin64 -l C:/cygwin/var/cache/setup -P openssl -P libssl-devel -P zlib -P zlib-devel -P ninja -P cmake -P gcc -P make -P autoconf && cd $PPD && openssl version && cygcheck -c && git clone --depth 1 --branch main https://github.com/open-quantum-safe/liboqs.git && cd liboqs && mkdir build && cd build && cmake .. -GNinja -DCMAKE_VERBOSE_MAKEFILE=ON -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DCMAKE_INSTALL_PREFIX=$LIBOQS_INSTALL -DOQS_BUILD_ONLY_LIB=ON && ninja -v && ninja install && cd ../.. && mkdir -p -m 0755 /var/empty && autoupdate && autoreconf && LDFLAGS=\"-Wl,--stack,20000000\" ./configure --without-openssl-header-check --with-liboqs-dir=$LIBOQS_INSTALL --with-libs=-lm && make && make install && TEST_SSH_UNSAFE_PERMISSIONS=1 make tests LTESTS=\"\" "
)
