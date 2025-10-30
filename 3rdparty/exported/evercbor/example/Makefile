all: CBORNondetTest

CBOR_LIB_PATH = $(realpath ..)
CBOR_INCLUDE_PATH = $(realpath ..)

# -Wno-pointer-sign because of string to uint8_t* conversion
CFLAGS += -Werror -I $(CBOR_INCLUDE_PATH) -g -Wno-pointer-sign

.PHONY: all

.PHONY: CBORNondetTest

CBORNondetTest: CBORNondetTest.exe
	./CBORNondetTest.exe

OBJ_FILES=main.o

$(OBJ_FILES): %.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

CBORNondetTest.exe: $(OBJ_FILES) $(CBOR_LIB_PATH)/CBORNondet.o
	$(CC) -o CBORNondetTest.exe $^

clean:
	rm -f CBORNondetTest.exe *.o

.PHONY: clean
