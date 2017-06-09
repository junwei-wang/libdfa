all: main #dec

main: main.c gf.o common.o dfa.o aes.o
#	CC -o $@ $?
dec: dfa_aes_dec_11.c
	CC -o $@ $?

%.o: %.c %.h

clean:
	rm -rf main dec
	rm *.o
