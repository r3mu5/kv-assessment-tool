ROOT=../build
include $(ROOT)/rules.mk

INCS = -I. -I/usr/include -Iinclude/

ifeq "$(shell echo $(WITH_LIBSYSTEMD))" "true"
	SH_LIBS = -lsystemd
endif

ifeq "$(shell echo $(KVAT_DEBUG))" "true"
	CFLAGS += -DDEBUG
endif

ST_LIBS = /usr/lib/x86_64-linux-gnu/libprocps.a
LIB_DIR = -L/usr/lib/x86_64-linux-gnu/

OBJS=	cli_utils.o 		\
	sys_info.o 		\
	proc_info.o 		\
	common_utils.o		\
	pmap.o			\
	kmm.o 			\
	main.o			\
	mmsearch-pid.o		\

all: kvat

kvat: $(OBJS)
	$(CC) $(CFLAGS) $(INCS) $(LIB_DIR) -o $@ $(OBJS) $(ST_LIBS) $(SH_LIBS)

clean_objs:
	@$(RM) $(OBJS)

clean_executables:
	@$(RM) *.h~ *.c~ Makefile~ *.orig.* kvat include/*.h~ \
	../include/*~ ../*~

clean:  clean_objs 		\
	clean_executables 	\



