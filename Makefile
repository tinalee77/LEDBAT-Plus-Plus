obj-m := tcp_ledbatpp.o
IDIR= /lib/modules/$(shell uname -r)/kernel/net/ipv4/
KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
default:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

install:
	install -v -m 644 tcp_ledbatpp.ko $(IDIR)
	depmod
	modprobe tcp_ledbatpp
	
uninstall:
	modprobe -r tcp_ledbatpp	

clean:
	rm -rf Module.markers modules.order Module.symvers tcp_ledbat.ko tcp_ledbat.mod.c tcp_ledbat.mod.o tcp_ledbat.o
	rm -rf Module.markers modules.order Module.symvers tcp_ledbatpp.ko tcp_ledbatpp.mod.c tcp_ledbatpp.mod.o tcp_ledbatpp.o tcp_ledbatpp.mod tcp_ledbatpp.dwo tcp_ledbatpp.mod.dwo