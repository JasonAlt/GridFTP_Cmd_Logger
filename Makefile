GLOBUS_LOCATION=/usr

#GLOBUS_INTERNAL_INCLUDES=-I/usr/src/debug/globus_gridftp_server_control-2.10
GLOBUS_INTERNAL_INCLUDES=-I/usr/src/debug/globus_gridftp_server_control-3.7/
GLOBUS_INCLUDES=-I/usr/include/globus -I/usr/lib64/globus/include

INCLUDES=$(GLOBUS_INTERNAL_INCLUDES) $(GLOBUS_INCLUDES)
CFLAGS=-fPIC -ggdb3 $(GLOBUS_INTERNAL_INCLUDES) $(GLOBUS_INCLUDES)

all:: libcmd_logger.so


libcmd_logger.so: cmd_logger.o
	$(CC) -shared -o $@ $^

clean::
	rm -f cmd_logger.o

clobber:: clean
	rm -f libcmd_logger.so
