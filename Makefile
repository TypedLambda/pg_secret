CURDIR := $(shell pwd)

CC = clang
FASTORE=./fastore
POSTGRES=`pg_config --includedir-server`
INCPATHS = -I/usr/include -I/usr/local/opt/openssl@1.1/include -I$(FASTORE) -I$(POSTGRES)
CFLAGS = -Wall -O3 $(INCPATHS) -march=native -fPIC
LDLIBS = -lgmp -lssl -lcrypto
LDPATH = -L/usr/lib -L/usr/local/opt/openssl@1.1/lib

BUILD = _build
TESTS = tests
SRC = $(FASTORE)/crypto.c $(FASTORE)/ore.c $(FASTORE)/ore_blk.c
OUTPUT = $(CURDIR)/secret.so
FASTORE_OBJ = $(patsubst $(FASTORE)/%.c,$(BUILD)/%.o, $(SRC))
OBJPATHS = $(FASTORE_OBJ) $(BUILD)/secret.o $(BUILD)/api.o $(BUILD)/b64.o

all: $(OBJPATHS) $(OUTPUT)

$(BUILD):
	@echo "Creating build dir..."
	mkdir -p $(BUILD)

$(BUILD)/secret.o: secret.c debug.h | $(BUILD)
	$(CC) $(CFLAGS) -o $@ -c $<

$(BUILD)/b64.o: b64.c | $(BUILD)
	$(CC) $(CFLAGS) -o $@ -c $<

$(BUILD)/api.o: api.c debug.h | $(BUILD)
	$(CC) $(CFLAGS) -o $@ -c $<

$(BUILD)/%.o: | $(BUILD)
	$(CC) $(CFLAGS) -o $@ -c $(FASTORE)/$*.c

$(OUTPUT): $(OBJPATHS)
	$(CC) $(CFLAGS) -bundle -flat_namespace -undefined suppress -o $(OUTPUT) $(OBJPATHS) $(LDPATH) $(LDLIBS)

clean:
	rm -rf $(BUILD)/*.o $(OUTPUT) $(TESTS) *~
