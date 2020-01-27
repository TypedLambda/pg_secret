MODULE_big = pgsecret
EXTENSION = pg_secret
DATA = pg_secret--0.5.sql
#DOCS = README.pg_secret

OBJS=siphash.o internal.o fastore/crypto.o fastore/ore_blk.o pgsecret.o
PG_CFLAGS=-I./fastore -I/usr/include/openssl/ -I/usr/local/opt/openssl@1.1/include -Wno-vla -Wno-declaration-after-statement -maes
PG_LDFLAGS=-lgmp -lssl -lcrypto -L/usr/local/opt/openssl@1.1/lib
PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
