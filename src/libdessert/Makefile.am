
AM_CPPFLAGS = -I$(top_srcdir)/include \
              -I../callbacks \
              -I../snmp \
              @PCAP_CFLAGS@ \
              @SNMP_CFLAGS@ \
              @PTHREAD_CFLAGS@ \
              -DVERSION=\"@VERSION@\"

lib_LTLIBRARIES = libdessert.la

libdessert_la_SOURCES = dessert_agentx.c \
                        dessert_core.c \
                        dessert_meshiface.c \
                        dessert_periodic.c \
                        dessert_cli.c \
                        dessert_log.c \
                        dessert_msg.c \
                        dessert_sysiface.c \
                        dessert_internal.h

libdessert_la_LIBADD = ../snmp/libdessertsnmp.la \
                       @SNMP_LIBS@ \
                       @PCAP_LIBS@ \
                       @CLI_LIBS@ \
                       @PTHREAD_LIBS@

libdessert_la_LDFLAGS = -version-number @LIBDESSERT_LIBRARY_VERSION@
