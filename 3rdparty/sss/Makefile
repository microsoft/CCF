CFLAGS = -Wall -g -O2
SRCS = hazmat.c randombytes.c sss.c tweetnacl.c
OBJS := ${SRCS:.c=.o}

all: libsss.a

libsss.a: randombytes/librandombytes.a $(OBJS)
	$(AR) -rcs libsss.a $^

randombytes/librandombytes.a:
	$(MAKE) -C randombytes librandombytes.a

# Force unrolling loops on hazmat.c
hazmat.o: CFLAGS += -funroll-loops

%.out: %.o randombytes/librandombytes.a
	$(CC) -o $@ $(CFLAGS) $(LDFLAGS) $^ $(LOADLIBES) $(LDLIBS)
	$(MEMCHECK) ./$@

test_hazmat.out: $(OBJS)
test_sss.out: $(OBJS)

.PHONY: check
check: test_hazmat.out test_sss.out

.PHONY: clean
clean:
	$(MAKE) -C randombytes $@
	$(RM) *.o *.gch *.a *.out
