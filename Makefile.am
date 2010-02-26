
ACLOCAL_AMFLAGS = -I m4

SUBDIRS = include src

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libdessert.pc

include doxygen-include.am

DISSECTORS = dissectors/DES-SERT.lua dissectors/DES-SERT-EXT-ETH.lua dissectors/DES-SERT-EXT-PING.lua dissectors/DES-SERT-EXT-TRACE.lua
MIBS = DESSERT-MIB.txt
EXTRA_DIST = autogen.sh DES-SERT.doxyfile doxygen/html $(MIBS) $(DISSECTORS)

install-data-local: install-mibs install-dissectors

install-mibs: installdirs-mibs
	if [ $(install_mibs) -eq 1 ]; then \
		for i in $(MIBS) ; do \
			$(INSTALL_DATA) $$i $(DESTDIR)/$(with_mibsdir) ; \
		done ; \
	fi

uninstall-mibs:
	for i in $(MIBS) ; do \
		rm -f $(with_mibsdir)/$$i ; \
	done

installdirs-mibs:
	if [ $(install_mibs) -eq 1 ]; then \
		$(SHELL) $(top_srcdir)/mkinstalldirs $(DESTDIR)/$(with_mibsdir) ; \
	fi
	
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
		$(SHELL) $(top_srcdir)/mkinstalldirs $(DESTDIR)/$(with_dissectorsdir) ; \
	fi