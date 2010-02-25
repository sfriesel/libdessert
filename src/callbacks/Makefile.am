
AM_CPPFLAGS = -I$(top_srcdir)/include \
              -I../libdessert

noinst_LTLIBRARIES = libdessertcallbacks.la

libdessertcallbacks_la_SOURCES = \
        dessert_callbacks.h \
        dessert_ifaces.c \
        dessert_ping.c \
        dessert_trace.c \
        dessert_ip_ttl.c \
        dessert_drop_ipv6.c \
        dessert_drop_tuntap.c

libdessertcallbacks_la_LDFLAGS = -avoid-version
