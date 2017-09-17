ifneq ($(KERNELRELEASE),)
obj-m := vmrun.o
ccflags-y := -std=gnu11
else
KERNEL_TREE_PATH?=/lib/modules/$(shell uname -r)/build

all: vmrun.ko

vmrun.ko: vmrun.c
	make V=0 -C $(KERNEL_TREE_PATH) M=$(PWD) modules

clean:
	make V=0 -C $(KERNEL_TREE_PATH) M=$(PWD) clean

.PHONY: all clean
endif
