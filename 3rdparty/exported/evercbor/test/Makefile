all: CBORNondetTest

CBOR_LIB_PATH = $(realpath ..)
CBOR_INCLUDE_PATH = $(realpath ..)

CFLAGS += -Werror -I $(CBOR_INCLUDE_PATH)

.PHONY: all

.PHONY: CBORNondetTest

CBORNondetTest: CBORNondetTest.exe
	./CBORNondetTest.exe

OBJ_FILES=CBORNondetTest.o main.o qcbortests.o

$(OBJ_FILES): %.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

CBORNondetTest.exe: $(OBJ_FILES) $(CBOR_LIB_PATH)/CBORNondet.o
	$(CC) -o CBORNondetTest.exe $^

clean:
	rm -f CBORNondetTest.exe *.o

.PHONY: clean
