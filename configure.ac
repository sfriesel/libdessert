#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.61])
AC_INIT([libdessert], [0.91], [des-sert@spline.inf.fu-berlin.de])
AM_INIT_AUTOMAKE([-Wall gnu dist-bzip2])
AC_CONFIG_MACRO_DIR([m4])

AC_CONFIG_SRCDIR([src/libdessert/dessert_core.c])
AC_CONFIG_HEADERS([config.h])

LIBDESSERT_LIBRARY_VERSION=1:1:0
AC_SUBST([LIBDESSERT_LIBRARY_VERSION])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LN_S

# Checks for libtool

# Debian Stable has no libtool2 yet so use old invocation
#LT_INIT
AM_PROG_LIBTOOL

# Checks for net-snmp-config
AC_CHECK_NET_SNMP

AC_SUBST([SNMP_LIBS])
AC_SUBST([SNMP_CFLAGS])

# Checks for pcap-config
AC_CHECK_PCAP

AC_SUBST([PCAP_LIBS])
AC_SUBST([PCAP_CFLAGS])

# Checks for libcli

AC_CHECK_HEADERS([libcli.h])

AC_SEARCH_LIBS([cli_print],
               [cli],
               [AC_DEFINE([CLI_LIBS],[-lcli],[defines linkoption for libcli])],
               [AC_MSG_ERROR([libcli could not found, please install development package of libcli])]
)

AC_SUBST([CLI_LIBS])

# Checks for libraries.

AX_PTHREAD(,[
AC_MSG_ERROR([Your system does not support a pthread variant, libdessert will not work])
])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netinet/in.h stdint.h stdlib.h string.h sys/ioctl.h sys/socket.h syslog.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_INT32_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_REALLOC
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
DX_INIT_DOXYGEN([${PACKAGE_NAME}], [DES-SERT.doxyfile], [doxygen])

AC_CONFIG_FILES([Makefile
                src/Makefile
                src/snmp/Makefile
                src/callbacks/Makefile
                src/libdessert/Makefile
                include/Makefile
                libdessert.pc
                ])

AC_ARG_WITH(mibsdir,
		[  --with-mibsdir=DIR      Directory to install mibs. @<:@DATAROOTDIR/mibs@:>@],
		[ AC_SUBST(with_mibsdir) ])

AS_IF([test -z "$with_mibsdir"], [with_mibsdir="$datarootdir/mibs"; echo "Installing MIBs to default dir: $with_mibsdir"], [echo "Installing MIBs to dir: $with_mibsdir"])

#AC_ARG_VAR([SHLIB_CFLAGS],
#          [additional CFLAGS used when building shared libraries])
#AC_SUBST(SHLIB_CFLAGS)

AC_OUTPUT
