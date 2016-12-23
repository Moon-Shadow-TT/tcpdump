main :
	nasm -f elf64 change.asm -o change.o 
	gcc -o tcpdump change.o tcpdump.c
.PHONY : clean
clean :
	rm -f change.o tcpdump
