MODULE_NAME	= myfw

SRC := helpers/netlink_helper.c hooks/hook_main.c mod_main.c

KDIR := /lib/modules/$(shell uname -r)/build

$(MODULE_NAME)-objs = $(SRC:.c=.o)

obj-m := $(MODULE_NAME).o
PWD := $(shell pwd)

EXTRA_CFLAGS := -I$(src)/include -I$(src)/hooks -I$(src)/helpers
#ccflags-y := -I$(PWD)/include -I$(PWD)/hooks

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:                                  
	$(MAKE) -C $(KDIR) M=$(PWD) modules clean
	rm -rf modules.order
	rm -f *.symvers
