APP_NAME ?= s3slower
VERSION ?= 0.2.0
# Timestamped release so every rpm build revs automatically unless overridden
ITERATION ?= $(shell date +%Y%m%d%H%M%S)
RELEASE ?= $(ITERATION)
ARCH ?= $(shell uname -m)

PREFIX ?= /usr
BINDIR ?= $(PREFIX)/bin
SYSCONFDIR ?= /etc/$(APP_NAME)
LOGDIR ?= /opt/s3slower

DISTDIR ?= dist
RPM_TOPDIR := $(abspath $(DISTDIR)/rpmbuild)
TARBALL := $(DISTDIR)/$(APP_NAME)-$(VERSION).tar.gz

FPM ?= fpm
RPMBUILD ?= rpmbuild

FPM_COMMON_ARGS = -s dir \
	-n $(APP_NAME) \
	-v $(VERSION) \
	--iteration $(ITERATION) \
	--architecture $(ARCH) \
	--license MIT \
	--config-files $(SYSCONFDIR)/config.yaml \
	--after-install packaging/postinstall.sh \
	--directories $(LOGDIR) \
	s3slower.py=$(BINDIR)/s3slower \
	packaging/config.yaml=$(SYSCONFDIR)/config.yaml \
	README.md=/usr/share/doc/$(APP_NAME)/README.md \
	LICENSE=/usr/share/doc/$(APP_NAME)/LICENSE \
	requirements.txt=/usr/share/doc/$(APP_NAME)/requirements.txt

.PHONY: deb rpm rpm_fpm clean distdir

distdir:
	mkdir -p $(DISTDIR)

$(TARBALL): distdir
	tar czf $(TARBALL) --transform "s|^|$(APP_NAME)-$(VERSION)/|" \
		s3slower.py README.md LICENSE requirements.txt packaging/config.yaml packaging/postinstall.sh Makefile scripts

rpm: $(TARBALL)
	mkdir -p $(RPM_TOPDIR)/{BUILD,RPMS,SOURCES,SPECS,SRPMS,TMP}
	cp $(TARBALL) $(RPM_TOPDIR)/SOURCES/
	$(RPMBUILD) -bb packaging/s3slower.spec \
		--define "_topdir $(RPM_TOPDIR)" \
		--define "_sourcedir $(RPM_TOPDIR)/SOURCES" \
		--define "_rpmdir $(RPM_TOPDIR)/RPMS" \
		--define "_srcrpmdir $(RPM_TOPDIR)/SRPMS" \
		--define "_tmppath $(RPM_TOPDIR)/TMP" \
		--define "version $(VERSION)" \
		--define "release $(RELEASE)"
	@echo "RPMs available under $(RPM_TOPDIR)/RPMS"

rpm_fpm:
	$(FPM) $(FPM_COMMON_ARGS) -t rpm \
		--description "S3 latency tracer with TLS and HTTP probes" \
		--depends python3 --depends bcc --depends python3-bcc \
		--depends python3-pyyaml --depends python3-prometheus-client

deb:
	$(FPM) $(FPM_COMMON_ARGS) -t deb \
		--description "S3 latency tracer with TLS and HTTP probes" \
		--depends python3 --depends bcc --depends python3-bcc \
		--depends python3-yaml --depends python3-prometheus-client

clean:
	rm -f *.deb *.rpm
	rm -rf $(DISTDIR)
