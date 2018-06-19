CC := gcc
#TARGET := arm64
TARGET := x86
KERNEL := $(shell uname -r)
KERNELHEADERS := /lib/modules/$(KERNEL)/build/include
ASMHEADERS := /lib/modules/$(KERNEL)/build/arch/$(TARGET)/include/
all:
	$(CC) -Wall -I$(KERNELHEADERS) -I$(ASMHEADERS) core_file_gen.c -o core_file_gen
