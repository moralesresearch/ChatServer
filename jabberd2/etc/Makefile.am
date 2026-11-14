LIBTOOL += --quiet

# ChatServer: these are installed by install-data-local below, not as
# sysconf_DATA, so that they never exist with any mode but their final one:
# the configuration holds the router secret. CONFIG_INSTALL_FLAGS can add
# an owner and group (the top-level Makefile passes -o root -g jabber).
config_files = c2s.xml.dist router.xml.dist s2s.xml.dist sm.xml.dist jabberd.cfg.dist router-users.xml.dist router-filter.xml.dist
CONFIG_INSTALL_FLAGS = -m 640
noinst_DATA = $(config_files)
# ChatServer: no upstart or systemd files; FreeBSD uses rc.d (freebsd/rc.d/chatserver)
configs = $(config_files)
EXTRA_DIST = $(config_files:%.dist=%.dist.in)

SUBDIRS = templates

jabberd_bin = router sm s2s c2s

edit = sed \
	-e 's,@package\@,$(PACKAGE),g' \
	-e 's,@sysconfdir\@,$(sysconfdir),g' \
	-e 's,@localstatedir\@,$(localstatedir),g' \
	-e 's,@bindir\@,$(bindir),g' \
	-e 's,@libdir\@,$(libdir),g' \
	-e 's,@pkglibdir\@,$(pkglibdir),g'

$(configs): $(config_files:%.dist=@srcdir@/%.dist.in)
	@echo "generating $@ from $@.in"; \
    edit='$(edit)'; \
    list='$(jabberd_bin)'; for p in $$list; do \
      bin=`echo "$$p" | sed 's,^.*/,,;$(transform);s/$$/$(EXEEXT)/'`; \
      edit="$$edit -e s,@jabberd_$$p\_bin\\@,$$bin,g"; \
    done; \
	rm -f $@ $@.tmp; \
	eval "$$edit < @srcdir@/$@.in > $@.tmp"; \
	mv $@.tmp $@ 
    
install-data-local: $(config_files)
	$(MKDIR_P) $(DESTDIR)$(sysconfdir)
	@list='$(config_files)'; for p in $$list; do \
      dest=`echo $$p | sed -e s/.dist//`; \
	  echo " $(INSTALL) $(CONFIG_INSTALL_FLAGS) $$p $(DESTDIR)$(sysconfdir)/$$p"; \
	  $(INSTALL) $(CONFIG_INSTALL_FLAGS) $$p $(DESTDIR)$(sysconfdir)/$$p || exit 1; \
	  if test -f $(DESTDIR)$(sysconfdir)/$$dest; then \
        echo "$@ will not overwrite existing $(DESTDIR)$(sysconfdir)/$$dest"; \
      else \
	    echo " $(INSTALL) $(CONFIG_INSTALL_FLAGS) $$p $(DESTDIR)$(sysconfdir)/$$dest"; \
	    $(INSTALL) $(CONFIG_INSTALL_FLAGS) $$p $(DESTDIR)$(sysconfdir)/$$dest || exit 1; \
	  fi; \
	done

clean-local:
	rm -f $(configs)
