obj-m := hook.o

hook-y := trapper.o
# mem.o libudis86/decode.o libudis86/itab.o libudis86/udis86.o

INC=/lib/modules/$(shell uname -r)/build/arch/x86/include

all: traps user

user: user.c
	gcc -Wall -Werror -I$(INC)/generated/uapi -I$(INC)/uapi user.c -o user
traps:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -f user
