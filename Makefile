obj-m += pmc.o

CFLAGS = -Wall
UNAME = $(shell uname -r)
BUILD = /lib/modules/$(UNAME)/build

all:
	make -C $(BUILD) M=$(PWD) modules

clean:
	make -C $(BUILD) M=$(PWD) clean

rwpmc: rwpmc.c
