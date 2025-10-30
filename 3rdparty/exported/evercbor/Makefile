all: extract

.PHONY: all

CFLAGS += -O3 -I . -Wall

OUTPUT_DIRECTORY:=.

extract: $(OUTPUT_DIRECTORY)/CBORNondet.o

.PHONY: extract

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

all-tests: test example

.PHONY: all-tests

test: extract
	+$(MAKE) -C $@

.PHONY: test

example: extract
	+$(MAKE) -C $@

.PHONY: example

clean-o:
	rm -f *.o

.PHONY: clean-o

clean: clean-o test.clean example.clean

.PHONY: clean

%.clean:
	+$(MAKE) -C $(basename $@) clean

.PHONY: %.clean
