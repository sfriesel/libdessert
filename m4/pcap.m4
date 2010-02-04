AC_DEFUN([AC_CHECK_PCAP],[
AC_MSG_CHECKING([Searching for pcap lib])
AC_CHECK_PROG([PCAP_LIBS],[pcap-config],[`echo "-L/usr/lib -lpcap"`],[none])
AC_CHECK_PROG([PCAP_CFLGAS],[pcap-config],[`pcap-config --cflags`],[none])
if test x"${PCAP_LIBS}" = "xnone"; then
AC_MSG_ERROR([pcap-config not found, please install the development package of libpcap])
else
AC_MSG_RESULT([found pcap])
fi
])
