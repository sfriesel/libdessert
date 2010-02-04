
ACLOCAL_AMFLAGS = -I m4

SUBDIRS = include src

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libdessert.pc

include doxygen-include.am

EXTRA_DIST = autogen.sh DES-SERT.doxyfile doxygen/html DESSERT-MIB.txt
info_TEXINFOS = libdessert.texi

MIBS = DESSERT-MIB.txt

install-mibs: installdirs-mibs
	echo "installing MIBs to $(with_mibsdir)"
	@for i in $(MIBS) ; do \
		$(INSTALL_DATA) $$i $(with_mibsdir) ; \
	done

uninstall-mibs:
	@for i in $(MIBS) ; do \
		rm -f $(with_mibsdir)/$$i ; \
	done

installdirs-mibs:
	@$(SHELL) $(top_srcdir)/mkinstalldirs $(with_mibsdir)
	
