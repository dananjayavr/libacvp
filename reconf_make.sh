autoreconf --install
./configure --with-ssl-dir=/usr/include/openssl --with-libcurl-dir=/usr/include/x86_64-linux-gnu/curl/ --disable-lib --with-libacvp-dir=/usr/local/acvp 
cd app
# Remove CFLAGS=-DDEBUG CFLAGS="-g -O0" below to generate a 'relase' build
make clean; make CFLAGS=-DDEBUG CFLAGS="-g -O0" -j $(nproc)