
ACLOCAL_AMFLAGS = -I m4

SUBDIRS = include src

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libdessert.pc

include doxygen-include.am

EXTRA_DIST = autogen.sh DES-SERT.doxyfile doxygen/html DESSERT-MIB.txt

MIBS = DESSERT-MIB.txt

install-mibs: installdirs-mibs
	@for i in $(MIBS) ; do \
		$(INSTALL_DATA) $$i $(DESTDIR)/$(with_mibsdir) ; \
	done

uninstall-mibs:
	@for i in $(MIBS) ; do \
		rm -f $(with_mibsdir)/$$i ; \
	done

installdirs-mibs:
	@$(SHELL) $(top_srcdir)/mkinstalldirs $(DESTDIR)/$(with_mibsdir)
	
