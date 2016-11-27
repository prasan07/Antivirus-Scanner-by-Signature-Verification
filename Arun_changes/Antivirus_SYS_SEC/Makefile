obj-m := hook.o

hook-y := trapper.o mem.o libudis86/decode.o libudis86/itab.o libudis86/udis86.o

INC=/lib/modules/$(shell uname -r)/build/arch/x86/include

all: traps user

user: user.c
	gcc -Wall -Werror -I$(INC)/generated/uapi -I$(INC)/uapi user.c -o user
traps:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -f user

#answer-y: user libudis86/decode.o libudis86/itab.o libudis86/udis86.o main.o mem.o

#obj-m := trapper.o
#obj-m := answer.o
#obj-y := libudis86/
#PATHS=/lib/modules/$(shell uname -r)/build/Antivirus/libudis86
#NEWINC=/lib/modules/$(shell uname -r)/build/arch/x86/include/include
#LDLIBS += -L/usr/local/lib/
#answer-y: user traps libudis86/built-in.o


#trapper-y: user traps mem.o libudis86/decode.o libudis86/itab.o libudis86/udis86.o libudis86/built-in.o

#traps:
#	make -Wall -Werror -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	
#traps:
#	make -Wall -Werror -I$(PATHS) -ludis86 -C /lib/modules/$(shell uname -r)/build M=$(PWD)

#traps:
#	make -Wall -Werror -I$(NEWINC) -C /lib/modules/$(shell uname -r)/build -ludis86 M=$(PWD) modules
