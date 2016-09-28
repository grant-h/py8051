VEX_PATH?=../vex/

UNAME := $(shell uname)
ifeq ($(UNAME), Darwin)
	LIBRARY_FILE=libpy8051.dylib
endif
ifeq ($(UNAME), Linux)
	LIBRARY_FILE=libpy8051.so
endif

${LIBRARY_FILE}: guest_8051_disasm.c
	gcc -O2 -shared -fPIC --std=c99 -o ${LIBRARY_FILE} guest_8051_disasm.c -Wl,-soname,libpy8051.so

clean:
	rm -f ${LIBRARY_FILE}
