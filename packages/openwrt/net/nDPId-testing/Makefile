include $(TOPDIR)/rules.mk

PKG_NAME:=nDPId-testing
PKG_VERSION:=1.0
PKG_RELEASE:=$(AUTORELEASE)

ifneq ($(wildcard /artifacts),)
PKG_DIRECTORY:=/artifacts
else
PKG_DIRECTORY:=../../../..
endif
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)

PKG_MAINTAINER:=Toni
PKG_LICENSE:=GPL-3
PKG_LICENSE_FILES:=COPYING

CMAKE_INSTALL:=1

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

define Package/nDPId-testing
 TITLE:=nDPId is a tiny nDPI based daemons / toolkit (nDPId source repository)
 SECTION:=net
 CATEGORY:=Network
 DEPENDS:=@!SMALL_FLASH @!LOW_MEMORY_FOOTPRINT +libpcap +zlib +LIBNDPI_GCRYPT:libgcrypt
 URL:=http://github.com/lnslbrty/nDPId
endef

define Package/nDPId-testing/description
  nDPId is a set of daemons and tools to capture, process and classify network flows.
  It's only dependencies (besides a half-way modern c library and POSIX threads) are libnDPI (>= 3.6.0 or current github dev branch) and libpcap.
endef

define Package/nDPId-testing/config
config NDPID_TESTING_COLLECTD_SUPPORT
   bool "nDPId collectd support"
   depends on PACKAGE_nDPId-testing && PACKAGE_collectd-mod-exec && !CONFIG_NDPID_COLLECTD_SUPPORT
   default n
   help
     This option enables collectd to gather nDPId statistics via plugin-exec.
     Disabled by default.
endef

CMAKE_OPTIONS += -DBUILD_EXAMPLES=ON
CMAKE_OPTIONS += -DBUILD_NDPI=OFF
CMAKE_OPTIONS += -DNDPI_NO_PKGCONFIG=ON
CMAKE_OPTIONS += -DENABLE_ZLIB=ON
CMAKE_OPTIONS += -DENABLE_SANITIZER=OFF
CMAKE_OPTIONS += -DENABLE_MEMORY_PROFILING=OFF
CMAKE_OPTIONS += -DNEED_LINKING_AGAINST_LIBM=ON
CMAKE_OPTIONS += -DSTATIC_LIBNDPI_INSTALLDIR="$(PKG_BUILD_DIR)/libnDPI/install"

TARGET_CFLAGS += -DLIBNDPI_STATIC=1
TARGET_CFLAGS += -Werror

ifneq ($(CONFIG_LIBNDPI_GCRYPT),)
CMAKE_OPTIONS += -DNDPI_WIDTH_GCRYPT=ON
endif

ifdef NDPID_TESTING_COLLECTD_SUPPORT
define Package/nDPId-testing/install-collectd-files
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/bin/nDPIsrvd-collectd $(1)/usr/bin/nDPIsrvd-testing-collectd
endef
endif

define Build/Prepare
	@echo 'tar: $(DL_DIR)/$(PKG_SOURCE)'
	@echo 'PKG_DIRECTORY=$(PKG_DIRECTORY)'
	@echo 'PKG_SOURCE_SUBDIR=$(PKG_SOURCE_SUBDIR)'
	tar \
		--exclude-tag-all='gcov.css' \
		--exclude-tag-all='cmake_install.cmake' \
		--exclude='libnDPI-*.tar' \
		--exclude='nDPId-*.tar.bz2' \
		--exclude='libnDPI' \
		--exclude='test' \
		--exclude-vcs \
		--exclude-vcs-ignores \
		--transform 's,^,$(PKG_SOURCE_SUBDIR)/,' \
		-czf "$(DL_DIR)/$(PKG_SOURCE)" -C "$(PKG_DIRECTORY)" .
	tar -tzf "$(DL_DIR)/$(PKG_SOURCE)"
	$(PKG_UNPACK)
	cd '$(PKG_BUILD_DIR)' && patch -p1 < $(PKG_BUILD_DIR)/packages/openwrt/net/nDPId-testing/001-enable-in-source-build.patch
	env \
		CC="$(TARGET_CC)" \
		AR="$(TARGET_AR)" \
		RANLIB="$(TARGET_RANLIB)" \
		CFLAGS="$(TARGET_CFLAGS)" \
		CPPFLAGS="$(TARGET_CPPFLAGS)" \
		LDFLAGS="$(TARGET_LDFLAGS)" \
		MAKE_PROGRAM="$(MAKE)" \
		$(PKG_BUILD_DIR)/scripts/get-and-build-libndpi.sh
endef

define Package/nDPId-testing/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/sbin/nDPId $(1)/usr/sbin/nDPId-testing

	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/bin/nDPId-test $(1)/usr/bin/nDPId-testing-test
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/bin/nDPIsrvd $(1)/usr/bin/nDPIsrvd-testing
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/bin/nDPIsrvd-analysed $(1)/usr/bin/nDPIsrvd-testing-analysed
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/bin/nDPIsrvd-captured $(1)/usr/bin/nDPIsrvd-testing-captured
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/bin/nDPIsrvd-collectd $(1)/usr/bin/nDPIsrvd-testing-collectd
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/bin/nDPIsrvd-json-dump $(1)/usr/bin/nDPIsrvd-testing-json-dump

	$(INSTALL_DIR) $(1)/etc/init.d/
	$(INSTALL_BIN) $(PKG_NAME).init $(1)/etc/init.d/$(PKG_NAME)
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) $(PKG_NAME).config $(1)/etc/config/$(PKG_NAME)

	$(call Package/nDPId-testing/install-collectd-files)
endef

$(eval $(call BuildPackage,nDPId-testing))
