TARGET := AARCH64

CC := gcc
CFLAGS += -Wall -g -DEM_ARCH=EM_$(TARGET)
CFLAGS += -I./include/

all:
	$(CC) $(CFLAGS) core_file_gen.c -o core_file_gen
	
clean:
	rm -f *.o core_file_gen