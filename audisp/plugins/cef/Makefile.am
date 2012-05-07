# Makefile.am --
# Copyright 2008 Red Hat Inc., Durham, North Carolina.
# Copyright 2012 Mozilla Corporation
# All Rights Reserved.
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
# Authors:
#   Steve Grubb <sgrubb@redhat.com>
#   Guillaume Destuynder <gdestuynder@mozilla.com>
# 

CONFIG_CLEAN_FILES = Makefile.in *.loT *.rej *.orig
EXTRA_DIST = audit-cef.conf $(man_MANS)
AUTOMAKE_OPTIONS = no-dependencies
INCLUDES = -I${top_srcdir} -I${top_srcdir}/lib 
prog_confdir = $(sysconfdir)/audisp
prog_conf = 
plugin_confdir=$(prog_confdir)/plugins.d
plugin_conf = audit-cef.conf
man_MANS =

audisp_cef_SOURCES = audisp-cef.c
audisp_cef_CFLAGS = -fPIE -DPIE -g -D_REENTRANT -D_GNU_SOURCE -Wundef
audisp_cef_LDFLAGS = -pie -Wl,-z,relro $(gss_libs)

install-data-hook:
	mkdir -p -m 0750 ${DESTDIR}${plugin_confdir}
	$(INSTALL_DATA) -D -m 640 ${srcdir}/$(plugin_conf) ${DESTDIR}${plugin_confdir}

uninstall-hook:
	rm ${DESTDIR}${plugin_confdir}/$(plugin_conf)

