tmp_sources = app_main.c \
              app_aes.c \
              app_cli.c \
              app_cmac.c \
              app_des.c \
              app_drbg.c \
              app_dsa.c \
              app_ecdsa.c \
              app_hmac.c \
              app_kas.c \
              app_kdf.c \
              app_kda.c \
              app_rsa.c \
              app_sha.c \
              app_utils.c \
              ../crypto/cyclone_crypto/hash/sha256.c \
              ../crypto/cyclone_crypto/hash/sha3_512.c \
              ../crypto/cyclone_crypto/hash/sha224.c \
              ../crypto/cyclone_crypto/hash/sha3_384.c \
              ../crypto/cyclone_crypto/hash/sha3_256.c \
              ../crypto/cyclone_crypto/hash/sha3_224.c \
              ../crypto/cyclone_crypto/hash/sha512.c \
              ../crypto/cyclone_crypto/hash/sha512_224.c \
              ../crypto/cyclone_crypto/hash/sha512_256.c \
              ../crypto/cyclone_crypto/hash/sha384.c \
              ../crypto/cyclone_crypto/hash/sha1.c \
              ../crypto/cyclone_crypto/xof/keccak.c \
              ../crypto/cyclone_crypto/xof/shake.c \
              ../crypto/cyclone_crypto/cipher/aes.c \
              ../crypto/cyclone_crypto/cipher_modes/cbc.c \
              ../crypto/cyclone_crypto/aead/gcm.c \
              ../crypto/common/cpu_endian.c \
              ../crypto/common/os_port_posix.c \
              ../crypto/common/debug.c \
              app_fips_lcl.h \
              app_fips_init_lcl.h \
              app_lcl.h \
              ../crypto/os_port_config.h \
              ../crypto/crypto_config.h \
              ../crypto/core/crypto.h \
              ketopt.h

if !BUILD_APP_AS_LIB
bin_PROGRAMS = acvp_app

acvp_app_includedir=$(includedir)/acvp
acvp_app_SOURCES = ${tmp_sources}
acvp_app_CFLAGS = -g -fPIE $(LIBACVP_CFLAGS) $(SSL_CFLAGS) $(FOM_CFLAGS) $(SAFEC_CFLAGS) -I../crypto -I../crypto/common -I../crypto/cyclone_crypto
acvp_app_LDFLAGS = $(LIBACVP_LDFLAGS) $(SSL_LDFLAGS) $(FOM_LDFLAGS)

if USE_LDL_CHECK
acvp_app_LDFLAGS += -ldl
endif

if USE_FOM
acvp_app_LDADD = $(FOM_OBJ_DIR)/fipscanister.o
endif

else
lib_LTLIBRARIES = libacvp_app.la
libacvp_app_includedir=${includedir}/acvp
libacvp_app_la_SOURCES = ${tmp_sources}

AM_CFLAGS = -g -fPIE $(LIBACVP_CFLAGS) $(SSL_CFLAGS) $(FOM_CFLAGS) $(SAFEC_CFLAGS) -DACVP_APP_LIB_WRAPPER
libacvp_app_la_LIBADD = $(LIBACVP_LDFLAGS) $(SSL_LDFLAGS) $(FOM_LDFLAGS)

libacvp_app_include_HEADERS = $(top_srcdir)/app/libacvp_app.h

if USE_LDL_CHECK
libacvp_app_la_LIBADD += -ldl
endif

if USE_FOM
libacvp_app_la_LIBADD += $(FOM_OBJ_DIR)/fipscanister.o
endif
endif
