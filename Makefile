MODULE_big = pgsecret
EXTENSION = pgsecret
DATA = pgsecret--0.5.sql
#DOCS = README.isbn_issn
#HEADERS_isbn_issn = isbn_issn.h

OBJS=siphash.o internal.o fastore/crypto.o ore_blk.o
PG_CFLAGS=-I./fastore -I/usr/include/openssl/ -maes
PG_LDFLAGS=-lgmp -lssl -lcrypto
PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
