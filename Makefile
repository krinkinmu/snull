ifneq ($(KERNELRELEASE),)

obj-m := snull.o
snull-y := main.o
CFLAGS_snull.o += -DDEBUG

else

KDIR ?= /lib/modules/`uname -r`/build

default:
	$(MAKE) -C $(KDIR) M=$$PWD

clean:
	rm -rf *.o *.ko *.order *.symvers *.mod.c

endif
