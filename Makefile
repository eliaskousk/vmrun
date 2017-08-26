KERNEL_TREE_PATH?=/lib/modules/$(shell uname -r)/build

obj-m := vmrun.o

all: vmrun.ko

vmrun.ko: vmrun.c
	make -C $(KERNEL_TREE_PATH) M=$(PWD) modules

clean:
	make -C $(KERNEL_TREE_PATH) M=$(PWD) clean

.PHONY: all clean
