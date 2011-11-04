ACLOCAL_AMFLAGS = -I m4

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libdessert.pc

include doc/doxygen-include.am

AM_CPPFLAGS = -Iinclude \
              -Isrc/dessert \
              @PCAP_CFLAGS@ \
              @PTHREAD_CFLAGS@

lib_LTLIBRARIES = libdessert.la

include_HEADERS = include/dessert.h

libdessert_la_SOURCES = src/libdessert/dessert_core.c \
                        src/libdessert/dessert_meshiface.c \
                        src/libdessert/dessert_periodic.c \
                        src/libdessert/dessert_signals.c \
                        src/libdessert/dessert_cli.c \
                        src/libdessert/dessert_log.c \
                        src/libdessert/dessert_msg.c \
                        src/libdessert/dessert_sysiface.c \
                        src/libdessert/dessert_utils.c \
                        src/libdessert/dessert_ping.c \
                        src/libdessert/dessert_trace.c \
                        src/libdessert/dessert_filter.c \
                        src/libdessert/dessert_internal.h

libdessert_la_LIBADD =  @PCAP_LIBS@ \
                        @CLI_LIBS@ \
                        @PTHREAD_LIBS@

if !ANDROID
    libdessert_la_SOURCES += src/libdessert/dessert_monitor.c
else
    AM_CPPFLAGS += -DANDROID
endif

libdessert_la_LDFLAGS = -version-number @LIBDESSERT_LIBRARY_VERSION@ -Wl,--no-undefined

if WITH_NET_SNMP
    AM_CPPFLAGS += -Isrc/snmp \
                   @SNMP_CFLAGS@

    libdessert_la_SOURCES += src/libdessert/dessert_agentx.c

    libdessert_la_LIBADD += src/snmp/libdessertsnmp.la \
                            @SNMP_LIBS@


    noinst_LTLIBRARIES = libdessertsnmp.la

    libdessertsnmp_la_SOURCES = \
        src/snmp/dessertAppParamsTable.c \
        src/snmp/dessertAppParamsTable.h \
        src/snmp/dessertAppParamsTable_oids.h \
        src/snmp/dessertAppParamsTable_data_access.c \
        src/snmp/dessertAppParamsTable_data_access.h \
        src/snmp/dessertAppParamsTable_data_get.c \
        src/snmp/dessertAppParamsTable_data_get.h \
        src/snmp/dessertAppParamsTable_data_set.c \
        src/snmp/dessertAppParamsTable_data_set.h \
        src/snmp/dessertAppParamsTable_enums.h \
        src/snmp/dessertAppParamsTable_interface.c \
        src/snmp/dessertAppParamsTable_interface.h \
        src/snmp/dessertAppStatsTable.c \
        src/snmp/dessertAppStatsTable.h \
        src/snmp/dessertAppStatsTable_enums.h \
        src/snmp/dessertAppStatsTable_oids.h \
        src/snmp/dessertAppStatsTable_data_access.c \
        src/snmp/dessertAppStatsTable_data_access.h \
        src/snmp/dessertAppStatsTable_data_get.c \
        src/snmp/dessertAppStatsTable_data_get.h \
        src/snmp/dessertAppStatsTable_data_set.c \
        src/snmp/dessertAppStatsTable_data_set.h \
        src/snmp/dessertAppStatsTable_interface.c \
        src/snmp/dessertAppStatsTable_interface.h \
        src/snmp/dessertMeshifTable.c \
        src/snmp/dessertMeshifTable.h \
        src/snmp/dessertMeshifTable_enums.h \
        src/snmp/dessertMeshifTable_oids.h \
        src/snmp/dessertMeshifTable_data_access.c \
        src/snmp/dessertMeshifTable_data_access.h \
        src/snmp/dessertMeshifTable_data_get.c \
        src/snmp/dessertMeshifTable_data_get.h \
        src/snmp/dessertMeshifTable_data_set.c \
        src/snmp/dessertMeshifTable_data_set.h \
        src/snmp/dessertMeshifTable_interface.c \
        src/snmp/dessertMeshifTable_interface.h \
        src/snmp/dessertObjects.c \
        src/snmp/dessertObjects.h \
        src/snmp/dessertSysifTable.c \
        src/snmp/dessertSysifTable.h \
        src/snmp/dessertSysifTable_enums.h \
        src/snmp/dessertSysifTable_oids.h \
        src/snmp/dessertSysifTable_interface.h \
        src/snmp/dessertSysifTable_data_access.c \
        src/snmp/dessertSysifTable_data_access.h \
        src/snmp/dessertSysifTable_data_get.c \
        src/snmp/dessertSysifTable_data_get.h \
        src/snmp/dessertSysifTable_data_set.c \
        src/snmp/dessertSysifTable_data_set.h \
        src/snmp/dessertSysifTable_interface.c \
        src/snmp/dessertSysifTable_subagent.c

        libdessertsnmp_la_LDFLAGS = -avoid-version
endif
DISSECTORS = dissectors/dessert.lua dissectors/dessert-ext-eth.lua dissectors/dessert-ext-ping.lua dissectors/dessert-ext-trace.lua
DOCS = doc/libdessert.doxyfile doxygen/html doc/*.doxygen doc/style/*.css doc/style/*.html doc/style/images/*.png doc/style/images/*.gif doc/style/images/*.eps
EXTRA_DIST = autogen.sh $(DOCS) $(DISSECTORS)

install-dissectors: installdirs-dissectors
	if [ $(install_dissectors) -eq 1 ]; then \
		for i in $(DISSECTORS) ; do \
			$(INSTALL_DATA) $$i $(DESTDIR)/$(with_dissectorsdir) ; \
		done ; \
	fi

uninstall-dissectors:
	for i in $(DISSECTORS) ; do \
		rm -f $(with_dissectorsdir)/$$i ; \
	done

installdirs-dissectors:
	if [ $(install_dissectors) -eq 1 ]; then \
		$(MKDIR_P) $(DESTDIR)/$(with_dissectorsdir) ; \
	fi
