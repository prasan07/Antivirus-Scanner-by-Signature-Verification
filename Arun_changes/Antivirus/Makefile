obj-m += trapper.o

INC=/lib/modules/$(shell uname -r)/build/arch/x86/include

all: user traps

user: user.c
	gcc -Wall -Werror -I$(INC)/generated/uapi -I$(INC)/uapi user.c -o user

traps:
	make -Wall -Werror -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -f user

