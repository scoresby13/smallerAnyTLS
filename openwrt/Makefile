include $(TOPDIR)/rules.mk

PKG_NAME:=anytls-tiny
PKG_VERSION:=0.2.0
PKG_RELEASE:=1

PKG_MAINTAINER:=scoresby13
PKG_LICENSE:=MIT
PKG_LICENSE_FILES:=LICENSE

include $(INCLUDE_DIR)/package.mk

define Package/anytls-tiny
  SECTION:=net
  CATEGORY:=Network
  SUBMENU:=Web Servers/Proxies
  TITLE:=Ultra-lightweight AnyTLS v2 Client
  URL:=https://github.com/scoresby13/smallerAnyTLS
  DEPENDS:=+libopenssl
endef

define Package/anytls-tiny/description
  smallerAnyTLS (anytls-tiny) is an ultra-compact AnyTLS v2 client implemented in C
  specifically optimized for embedded routers with strict flash memory constraints (e.g., 4MB/8MB/16MB).
  Includes SOCKS5, transparent TCP redirect, and anti-poisoning DNS forwarder.
endef

define Package/anytls-tiny/conffiles
/etc/config/anytls
endef

# Builds from this repository's src/ (link this directory into the SDK's package/ tree)
define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)/src
	$(CP) $(CURDIR)/../src/anytls-tiny.c $(PKG_BUILD_DIR)/src/
	$(CP) $(CURDIR)/../LICENSE $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(TARGET_CC) $(TARGET_CFLAGS) -Os -pipe -s \
		-fno-asynchronous-unwind-tables -ffunction-sections -fdata-sections -Wl,--gc-sections \
		$(PKG_BUILD_DIR)/src/anytls-tiny.c \
		-ldl -o $(PKG_BUILD_DIR)/anytls-tiny
endef

define Package/anytls-tiny/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/anytls-tiny $(1)/usr/bin/anytls-tiny

	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/etc/init.d/anytls $(1)/etc/init.d/anytls

	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_CONF) ./files/etc/config/anytls $(1)/etc/config/anytls
endef

$(eval $(call BuildPackage,anytls-tiny))
