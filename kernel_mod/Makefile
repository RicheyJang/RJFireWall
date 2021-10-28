MODULE_NAME	= myfw

SRC := helpers/netlink_helper.c helpers/app_helper.c hooks/hook_main.c mod_main.c

KDIR := /lib/modules/$(shell uname -r)/build

EXTRA_CFLAGS := -I$(src)/include -I$(src)/hooks -I$(src)/helpers

$(MODULE_NAME)-objs = $(SRC:.c=.o)
obj-m := $(MODULE_NAME).o
PWD := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

install:
	insmod $(PWD)/$(MODULE_NAME).ko
	$(MAKE) clean

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) modules clean
	rm -rf modules.order
	rm -f *.symvers
