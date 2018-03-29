stackvault-objs = jprobe.o mapper.o parseElf.o fileOps.o  utils_stack.o
obj-m += stackvault.o

all:
	#make CFLAGS+="-O3" -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	#make CFLAGS+="-O3" -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -f *.mod.c modules.order Module.symvers *.ko
