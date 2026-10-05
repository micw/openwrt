include $(TOPDIR)/rules.mk

PKG_NAME:=lt22m-bootloader
PKG_RELEASE:=1
PKG_LICENSE:=GPL-2.0-only
PKG_BUILD_DEPENDS:=uboot-mediatek

LOADER_IMAGE:=$(STAGING_DIR_IMAGE)/mt7628_tuoshi_lt22m-u-boot-with-spl.bin

include $(INCLUDE_DIR)/package.mk

define Package/lt22m-bootloader
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=LT22M bootloader inspection, backup and guarded flashing
  DEPENDS:=@TARGET_ramips_mt76x8 +mtd
endef

define Package/lt22m-bootloader/description
  Explicit, checked access to the LT22M bootloader partition. Installing
  this package never writes flash.
endef

define Build/Prepare
	test -s $(LOADER_IMAGE)
	mkdir -p $(PKG_BUILD_DIR)
endef

define Build/Compile
	$(TARGET_CC) $(TARGET_CFLAGS) -std=c99 -Wall -Wextra -O2 -o $(PKG_BUILD_DIR)/lt22m-image-check ./files/lt22m-image-check.c
endef

define Package/lt22m-bootloader/install
	$(INSTALL_DIR) $(1)/usr/sbin $(1)/usr/share/lt22m
	$(INSTALL_BIN) ./files/lt22m-bootloader $(1)/usr/sbin/lt22m-bootloader
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/lt22m-image-check $(1)/usr/sbin/lt22m-image-check
	$(INSTALL_DATA) $(LOADER_IMAGE) $(1)/usr/share/lt22m/u-boot-with-spl.bin
	sha256sum $(LOADER_IMAGE) | cut -d ' ' -f 1 > $(1)/usr/share/lt22m/bootloader.sha256
endef

$(eval $(call BuildPackage,lt22m-bootloader))
