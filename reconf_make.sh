autoreconf --install
./configure --with-ssl-dir=/usr/include/openssl --with-libcurl-dir=/usr/include/x86_64-linux-gnu/curl/ --disable-lib --with-libacvp-dir=/usr/local/acvp
cd app
make clean; make -j $(nproc)