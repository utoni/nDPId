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

include $(INCLUDE_DIR)/kernel.mk
include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/cmake.mk

define Package/nDPId-testing
 TITLE:=nDPId is a tiny nDPI based daemons / toolkit (nDPId source repository)
 SECTION:=net
 CATEGORY:=Network
 DEPENDS:=@!SMALL_FLASH @!LOW_MEMORY_FOOTPRINT +libpcap +zlib +LIBNDPI_GCRYPT:libgcrypt +NDPID_TESTING_INFLUXDB:libcurl +NDPID_TESTING_PFRING:libpfring
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

config NDPID_TESTING_LIBNDPI_COMMIT_HASH
   string "libnDPI commit hash"
   depends on PACKAGE_nDPId-testing
   default ""
   help
     Set the desired libnDPI git commit hash you want to link nDPId against.
     Leave empty to use the dev branch.
     Disabled by default.

config NDPID_TESTING_INFLUXDB
   bool "nDPIsrvd-influxdb"
   depends on PACKAGE_nDPId-testing && PACKAGE_libcurl
   default n
   help
     An InfluxDB push daemon. It aggregates various statistics gathered from nDPId.
     The results are sent to a specified InfluxDB endpoint.

config NDPID_TESTING_PFRING
   bool "PF_RING support"
   select PACKAGE_libpfring
   select PACKAGE_kmod-pf-ring
   default n
   help
     bla
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

ifneq ($(CONFIG_NDPID_TESTING_PFRING),)
CMAKE_OPTIONS += -DENABLE_PFRING=ON \
	-DPFRING_KERNEL_INC="$(KERNEL_BUILD_DIR)/PF_RING-8.4.0/kernel" \
	-DPFRING_INSTALLDIR="$(STAGING_DIR)/usr" \
	-DPFRING_LINK_STATIC=OFF
endif

ifneq ($(CONFIG_NDPID_TESTING_INFLUXDB),)
CMAKE_OPTIONS += -DENABLE_CURL=ON
endif

ifneq ($(CONFIG_LIBNDPI_GCRYPT),)
CMAKE_OPTIONS += -DNDPI_WIDTH_GCRYPT=ON
endif

ifdef CONFIG_NDPID_TESTING_COLLECTD_SUPPORT
define Package/nDPId-testing/install-collectd-files
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/usr/bin/nDPIsrvd-collectd $(1)/usr/bin/nDPIsrvd-testing-collectd
endef
endif

ifdef CONFIG_NDPID_TESTING_LIBNDPI_COMMIT_HASH
define Package/nDPId-testing/get-and-build-libndpi
	@echo 'Using commit hash: $(CONFIG_NDPID_TESTING_LIBNDPI_COMMIT_HASH)'
	env \
		CC="$(TARGET_CC)" \
		AR="$(TARGET_AR)" \
		RANLIB="$(TARGET_RANLIB)" \
		CFLAGS="$(TARGET_CFLAGS)" \
		CPPFLAGS="$(TARGET_CPPFLAGS)" \
		LDFLAGS="$(TARGET_LDFLAGS)" \
		MAKE_PROGRAM="$(MAKE)" \
		NDPI_COMMIT_HASH=$(CONFIG_NDPID_TESTING_LIBNDPI_COMMIT_HASH) \
		$(PKG_BUILD_DIR)/scripts/get-and-build-libndpi.sh
endef
else
define Package/nDPId-testing/get-and-build-libndpi
	@echo 'Using dev branch.'
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
endif

define Build/Prepare
	@rm -f '$(DL_DIR)/$(PKG_SOURCE)'
	@rm -rf '$(PKG_BUILD_DIR)/*'
	@echo 'tar: $(DL_DIR)/$(PKG_SOURCE)'
	@echo 'pwd: $(shell pwd)'
	@echo 'PKG_DIRECTORY=$(PKG_DIRECTORY)'
	@echo 'PKG_SOURCE_SUBDIR=$(PKG_SOURCE_SUBDIR)'
	cd '$(PKG_DIRECTORY)' && git archive --prefix '$(PKG_SOURCE_SUBDIR)/' -o '$(DL_DIR)/new_$(PKG_SOURCE)' HEAD
	mv '$(DL_DIR)/new_$(PKG_SOURCE)' '$(DL_DIR)/$(PKG_SOURCE)'; \
	$(PKG_UNPACK)
	cd '$(PKG_BUILD_DIR)' && patch -p1 < $(PKG_BUILD_DIR)/packages/openwrt/net/nDPId-testing/001-enable-in-source-build.patch
	$(call Package/nDPId-testing/get-and-build-libndpi)
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

	$(INSTALL_DIR) $(1)/etc/init.d/
	$(INSTALL_BIN) $(PKG_NAME).init $(1)/etc/init.d/$(PKG_NAME)
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) $(PKG_NAME).config $(1)/etc/config/$(PKG_NAME)

	$(call Package/nDPId-testing/install-collectd-files,$(1))
endef

$(eval $(call BuildPackage,nDPId-testing))
