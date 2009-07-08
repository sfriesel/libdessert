
SHLIB_VERSION = 0.84.0
SHLIB_COMPAT_VERSION = 0.81

MODULES=dessert_core.o dessert_log.o dessert_tun.o dessert_iface.o dessert_msg.o dessert_cli.o dessert_periodic.o

UNAME = $(shell uname | tr 'a-z' 'A-Z')
ifeq ($(UNAME),LINUX)
	LIBS = pthread pcap cli crypt
	CFLAGS += -ggdb -Wall -fPIC -DTARGET_$(UNAME) -D_GNU_SOURCE -DSHLIB_VERSION=\"$(SHLIB_VERSION)\"
	LDFLAGS += -dy -static-libgcc $(addprefix -l,$(LIBS))
	SHLIB = libdessert.so.$(SHLIB_VERSION)
	SHLIB_COMPAT = libdessert.so.$(SHLIB_COMPAT_VERSION)
	SHLIB_DEFAULT = libdessert.so
	SHLIB_LDFLAGS = -shared -Wl,-soname,$(SHLIB_COMPAT) -o $(SHLIB)
else ifeq ($(UNAME),DARWIN)
	LIBS = pthread pcap cli
	CFLAGS += -ggdb -Wall -fPIC -DTARGET_$(UNAME) -DTARGET_BSD -DSHLIB_VERSION=\"$(SHLIB_VERSION)\"
	LDFLAGS += $(addprefix -l,$(LIBS))
	SHLIB = libdessert.$(SHLIB_VERSION).dylib
	SHLIB_COMPAT = libdessert.$(SHLIB_COMPAT_VERSION).dylib
	SHLIB_DEFAULT = libdessert.dylib
	SHLIB_LDFLAGS = -dynamiclib -compatibility_version $(SHLIB_COMPAT_VERSION) -current_version $(SHLIB_VERSION) -o $(SHLIB)
else ifeq ($(UNAME),FREEBSD)
	LIBS = pcap cli crypt
	CFLAGS += -ggdb -Wall  -fPIC -DTARGET_$(UNAME) -DTARGET_BSD -DSHLIB_VERSION=\"$(SHLIB_VERSION)\" -pthread -I/usr/local/include -I/usr/include
	LDFLAGS += -dy -L/usr/local/lib -L/usr/lib $(addprefix -l,$(LIBS))
	SHLIB = libdessert.so.$(SHLIB_VERSION)
	SHLIB_COMPAT = libdessert.so.$(SHLIB_COMPAT_VERSION)
	SHLIB_DEFAULT = libdessert.so
	SHLIB_LDFLAGS = -shared -Wl,-soname,$(SHLIB_COMPAT) -o $(SHLIB)
endif

CFLAGS +=
LDFLAGS +=

all: libdessert.a $(SHLIB)

clean:
	rm -r *.o *.a *.so *.so.* *.dylib ||  true

install:
	echo "ECHO:: $(DIR_LIB) $(SHLIB)"
	install -d $(DIR_LIB) $(DIR_INCLUDE)
	install -m755 $(SHLIB) $(DIR_LIB)
	(cd $(DIR_LIB) ; ln -fs $(SHLIB) $(SHLIB_COMPAT))
	(cd $(DIR_LIB) ; ln -fs $(SHLIB) $(SHLIB_DEFAULT))
	install -m644 dessert.h $(DIR_INCLUDE)

libdessert.a: $(MODULES)
	$(AR) -r libdessert.a $(MODULES)
	ranlib libdessert.a

$(SHLIB): $(MODULES)
	$(CC) $(CFLAGS) $(LDFLAGS) $(SHLIB_LDFLAGS) $(MODULES) 
	ln -fs $(SHLIB) $(SHLIB_COMPAT)
	ln -fs $(SHLIB) $(SHLIB_DEFAULT)

tarball: clean
	tar -czf ../libdessert-$(SHLIB_VERSION).tar.gz *.c *.h Makefile
