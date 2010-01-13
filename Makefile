SHLIB_VERSION = 0.87.1
SHLIB_COMPAT_VERSION = 0.87

MODULES=dessert_core.o dessert_log.o dessert_sysiface.o dessert_meshiface.o dessert_msg.o dessert_cli.o dessert_periodic.o dessert_agentx.o

UNAME = $(shell uname | tr 'a-z' 'A-Z')
TARFILES = *.c *.h Makefile Intro.txt DES-SERT.doxyfile AUTHORS

PREFIX ?= $(DESTDIR)/usr
DIR_LIB=$(PREFIX)/lib
DIR_INCLUDE=$(PREFIX)/include

ifeq ($(UNAME),LINUX)
	LIBS = pthread pcap cli
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
	LIBS = pcap cli
	CFLAGS += -ggdb -Wall  -fPIC -DTARGET_$(UNAME) -DTARGET_BSD -DSHLIB_VERSION=\"$(SHLIB_VERSION)\" -pthread -I/usr/local/include -I/usr/include
	LDFLAGS += -dy -L/usr/local/lib -L/usr/lib $(addprefix -l,$(LIBS))
	SHLIB = libdessert.so.$(SHLIB_VERSION)
	SHLIB_COMPAT = libdessert.so.$(SHLIB_COMPAT_VERSION)
	SHLIB_DEFAULT = libdessert.so
	SHLIB_LDFLAGS = -shared -Wl,-soname,$(SHLIB_COMPAT) -o $(SHLIB)
endif

## >>> SNMP ##
NETSNMPCONFIG=net-snmp-config

STRICT_FLAGS = -Wstrict-prototypes
NETSNMPCFLAGS := $(shell $(NETSNMPCONFIG) --base-cflags) $(STRICT_FLAGS)
NETSNMPLIBS := $(shell $(NETSNMPCONFIG) --agent-libs)

SNMPMODULES = snmp/dessertObjects                    \
              snmp/dessertMeshifTable                \
              snmp/dessertMeshifTable_data_get       \
              snmp/dessertMeshifTable_data_set       \
              snmp/dessertMeshifTable_data_access    \
              snmp/dessertMeshifTable_interface      \
              snmp/dessertSysifTable                 \
              snmp/dessertSysifTable_data_get        \
              snmp/dessertSysifTable_data_set        \
              snmp/dessertSysifTable_data_access     \
              snmp/dessertSysifTable_interface       \
              snmp/dessertAppStatsTable              \
              snmp/dessertAppStatsTable_data_get     \
              snmp/dessertAppStatsTable_data_set     \
              snmp/dessertAppStatsTable_data_access  \
              snmp/dessertAppStatsTable_interface    \
              snmp/dessertAppParamsTable             \
              snmp/dessertAppParamsTable_data_get    \
              snmp/dessertAppParamsTable_data_set    \
              snmp/dessertAppParamsTable_data_access \
              snmp/dessertAppParamsTable_interface 

CFLAGS += $(NETSNMPCFLAGS)
LDFLAGS += $(NETSNMPLIBS)
MODULES += $(addsuffix .o,$(SNMPMODULES))
SNMPTARFILES = snmp/*.c snmp/*.h
## <<< SNMP ##

DOXYGEN = /usr/bin/doxygen
DOXYFILE = DES-SERT.doxyfile
DOXYGENTARFILES = doxygen/html/*


CFLAGS +=
LDFLAGS +=

all: doxygen libdessert.a $(SHLIB)

clean:
	rm -r *.o *.a *.so *.so.* *.dylib *.tar.gz ||  true
	rm snmp/*.o || true
	rm test/*.o || true
	rm test-periodic_add || true
	rm test-periodic_add-delete-modify-add || true
	rm test-periodic_wladimir || true
	rm test-meshif-iterator || true
	rm test-agentx-appstats || true
	rm test-agentx-appparams || true
	rm test-agentx || true
	rm -rf doxygen || true
	rm Manual.pdf || true

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

tarball: clean doxygen
	mkdir libdessert$(SHLIB_COMPAT_VERSION)-$(SHLIB_VERSION)
	cp -R $(TARFILES) libdessert$(SHLIB_COMPAT_VERSION)-$(SHLIB_VERSION)
	mkdir libdessert$(SHLIB_COMPAT_VERSION)-$(SHLIB_VERSION)/snmp
	cp -R $(SNMPTARFILES) libdessert$(SHLIB_COMPAT_VERSION)-$(SHLIB_VERSION)/snmp
	mkdir libdessert$(SHLIB_COMPAT_VERSION)-$(SHLIB_VERSION)/doxygen
	mkdir libdessert$(SHLIB_COMPAT_VERSION)-$(SHLIB_VERSION)/doxygen/html
	cp -R $(DOXYGENTARFILES) libdessert$(SHLIB_COMPAT_VERSION)-$(SHLIB_VERSION)/doxygen/html
	gzip -9 -c changelog > libdessert$(SHLIB_COMPAT_VERSION)-$(SHLIB_VERSION)/changelog.gz
	tar -czf libdessert$(SHLIB_COMPAT_VERSION)-$(SHLIB_VERSION).tar.gz libdessert$(SHLIB_COMPAT_VERSION)-$(SHLIB_VERSION)
	rm -rf libdessert$(SHLIB_COMPAT_VERSION)-$(SHLIB_VERSION)
	
doxygen: 
	(cat $(DOXYFILE); echo "PROJECT_NUMBER=$(SHLIB_VERSION)") | $(DOXYGEN) -
	
manual: doxygen
	cd doxygen/latex; $(MAKE) pdf
	cp doxygen/latex/refman.pdf Manual.pdf 	
	
test-periodic_add: test/test-periodic_add.o $(MODULES)
	$(CC)  -ggdb -Wall -DTARGET_$(UNAME) -D_GNU_SOURCE   $(NETSNMPCFLAGS) $(LDFLAGS)  -o test-periodic_add test/test-periodic_add.o $(MODULES)

test-periodic_add-delete-modify-add: test/test-periodic_add-delete-modify-add.o $(MODULES)
	$(CC)  -ggdb -Wall -DTARGET_$(UNAME) -D_GNU_SOURCE   $(NETSNMPCFLAGS) $(LDFLAGS)  -o test-periodic_add-delete-modify-add test/test-periodic_add-delete-modify-add.o $(MODULES)

test-periodic_wladimir: test/test-periodic_wladimir.o $(MODULES)
	$(CC)  -ggdb -Wall -DTARGET_$(UNAME) -D_GNU_SOURCE   $(NETSNMPCFLAGS) $(LDFLAGS)  -o test-periodic_wladimir test/test-periodic_wladimir.o $(MODULES)


test-agentx-appparams: test/test-agentx-appparams.o $(MODULES)
	$(CC)  -ggdb -Wall -DTARGET_$(UNAME) -D_GNU_SOURCE   $(NETSNMPCFLAGS) $(LDFLAGS)  -o test-agentx-appparams test/test-agentx-appparams.o $(MODULES)

test-agentx-appstats: test/test-agentx-appstats.o $(MODULES)
	$(CC)  -ggdb -Wall -DTARGET_$(UNAME) -D_GNU_SOURCE   $(NETSNMPCFLAGS) $(LDFLAGS)  -o test-agentx-appstats test/test-agentx-appstats.o $(MODULES)

test-meshif-iterator: test/test-meshif-iterator.o $(MODULES)
	$(CC)  -ggdb -Wall -DTARGET_$(UNAME) -D_GNU_SOURCE   $(NETSNMPCFLAGS) $(LDFLAGS)  -o test-meshif-iterator test/test-meshif-iterator.o $(MODULES)	

test-cli_getcfg: test/test-cli_getcfg.o $(MODULES)
	$(CC)  -ggdb -Wall -DTARGET_$(UNAME) -D_GNU_SOURCE   $(NETSNMPCFLAGS) $(LDFLAGS)  -o test-cli_getcfg test/test-cli_getcfg.o $(MODULES)	
	
	