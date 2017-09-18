all: demo guest.bin

demo: demo.o
	gcc demo.c -o demo -lpthread

guest.bin: guest.o
	ld -m elf_i386 --oformat binary -N -e _start -Ttext 0x10000 -o guest.bin guest.o

guest.o: guest.S
	as -32 guest.S -o guest.o
