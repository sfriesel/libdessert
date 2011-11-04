#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.61])
AC_INIT([libdessert],[1.07],[des-sert@spline.inf.fu-berlin.de])
AM_INIT_AUTOMAKE([-Wall gnu dist-bzip2 subdir-objects])
AC_CONFIG_MACRO_DIR([m4])

AC_CONFIG_SRCDIR([src/libdessert/dessert_core.c])
AC_CONFIG_HEADERS([config.h])

LIBDESSERT_LIBRARY_VERSION=1:13:1
AC_SUBST([LIBDESSERT_LIBRARY_VERSION])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LN_S

AM_PROG_CC_C_O

# Checks for libtool

LT_INIT

# Checks for net-snmp-config
AS_IF([test x$with_net_snmp == xyes],
      [
          #AC_MSG_CHECKING([Searching for net-snmp lib])
          AC_CHECK_PROG([NET_SNMP_CONFIG], [net-snmp-config], [yes], [no])
          
          AS_IF([test x${NET_SNMP_CONFIG} = xno],
                [AC_MSG_ERROR([net-snmp-config not found, please install the development package of net-snmp])]
          )
          AC_SUBST([SNMP_LIBS], [`net-snmp-config --agent-libs`])
          AC_SUBST([SNMP_CFLAGS], [`net-snmp-config --cflags`])
          
          AC_DEFINE([WITH_NET_SNMP], [1], [Enable or disable net-snmp support (default=no)])
          AC_CHECK_HEADERS([net-snmp/net-snmp-config.h],
                           [],
                           [AC_MSG_ERROR([net-snmp-config.h not found, please install libsnmp development package])])
      ],
)

# Checks for zlib support
CHECK_ZLIB

# Checks for pcap-config
AC_CHECK_PROG([PCAP_CONFIG],[pcap-config],[yes],[no])
AS_IF([test x${PCAP_CONFIG} = xno],
      [AC_MSG_ERROR([pcap-config not found, please install or upgrade the development package of libpcap])]
)
AC_SUBST([PCAP_LIBS], [`pcap-config --libs`])
AC_SUBST([PCAP_CFLAGS], [`pcap-config --cflags`])

AC_CHECK_HEADER([pcap.h],[],[AC_MSG_ERROR([pcap headers not found])])

# Checks for libcli
AC_CHECK_HEADERS([libcli.h])
AC_SEARCH_LIBS([cli_print],
               [cli],
               [AC_DEFINE([CLI_LIBS],[-lcli],[defines linkoption for libcli])],
               [AC_MSG_ERROR([libcli not be found])]
)
AC_SUBST([CLI_LIBS])

# Check for ut*
AC_CHECK_HEADERS([uthash.h utlist.h],,[AC_MSG_ERROR([Please install uthash from http://uthash.sourceforge.net/])])

AC_CHECK_HEADERS([iwlib.h],,[AC_MSG_ERROR([iwlib could not be found, please install development package of iwlib])])

# Checks for libraries.

AX_PTHREAD(,[AC_MSG_ERROR([Your system does not support a pthread variant, libdessert will not work])])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netinet/in.h stdint.h stdlib.h string.h sys/ioctl.h sys/socket.h syslog.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL

# Checks for library functions.
AC_FUNC_ALLOCA
AC_CHECK_FUNCS([gethostname gettimeofday localtime_r memmove memset socket strdup strerror strtol])

# Checking for documentation generation

DX_HTML_FEATURE([ON])
DX_CHM_FEATURE([OFF])
DX_CHI_FEATURE([OFF])
DX_MAN_FEATURE([OFF])
DX_RTF_FEATURE([OFF])
DX_XML_FEATURE([OFF])
DX_PDF_FEATURE([ON])
DX_PS_FEATURE([OFF])
DX_INIT_DOXYGEN([${PACKAGE_NAME}], [doc/libdessert.doxyfile], [doxygen])

AC_CONFIG_FILES([Makefile
                libdessert.pc
                ])

AC_ARG_WITH(net-snmp,
        [AS_HELP_STRING([--with-net-snmp], [enable net-snmp support @<:@default=no@:>@])],
        [],
        [with_net_snmp=no])
AC_SUBST(with_net_snmp)
AM_CONDITIONAL([WITH_NET_SNMP], [test "x$with_net_snmp" != xno])

AC_ARG_ENABLE(dissectors, [  --enable-dissectors     install Wireshark dissectors @<:@Default=no@:>@], [install_dissectors=1], [install_dissectors=0])
AC_SUBST(install_dissectors)

AC_ARG_WITH(dissectorsdir,
        [  --with-dissectorsdir=DIR    Directory to install Wireshark dissectors. @<:@DATAROOTDIR/wireshark/plugins/@:>@],
        [ AC_SUBST(with_dissectorsdir) ],
        [ AC_SUBST(with_dissectorsdir, "$datarootdir/wireshark/plugins")])

AC_ARG_ENABLE(android-build,
    AS_HELP_STRING([--enable-android-build], [enables build to be compiled for android @<:@Default=no@:>@]),
    [do_android_build=1],
    [do_android_build=0])
AC_SUBST(do_android_build)
AM_CONDITIONAL([ANDROID], [test $do_android_build -eq 1])

# Checks for special android library libpthreadex

AS_IF([test $do_android_build -eq 1],
   [AC_CHECK_HEADERS([pthreadex.h])
    AC_SEARCH_LIBS([pthread_rwlock_unlock],
        [pthreadex],
        [],
        [AC_MSG_ERROR([pthreadex could not be found, you need to manually build this special library])])
   ]
)

AC_OUTPUT
