BOFNAME := self_delete
CC_x64 := x86_64-w64-mingw32-gcc

all:
	$(CC_x64) -Wno-unused-variable -o ../dist/$(BOFNAME).x64.o -c main.c -masm=intel

clean:
	rm -f ../dist/$(BOFNAME).x64.o
