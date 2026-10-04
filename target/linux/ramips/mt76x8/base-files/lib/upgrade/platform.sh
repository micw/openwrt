#
# Copyright (C) 2010 OpenWrt.org
#

PART_NAME=firmware
REQUIRE_IMAGE_METADATA=1

RAMFS_COPY_BIN='fw_printenv fw_setenv sha256sum dumpimage fwtool jsonfilter'
RAMFS_COPY_BIN="$RAMFS_COPY_BIN cmp head tr mktemp lt22m-image-check"
RAMFS_COPY_DATA='/etc/fw_env.config /var/lock/fw_printenv.lock'

# The stock loader uses two firmware slots. The virtual OpenWrt firmware MTD
# concatenates only A, spare and tail. Storage and B are writable for an
# explicitly guarded layout transition, but stock upgrades must preserve them.
lt22m_stock_check_device() {
	local expected number part bytes offset writable flags digest sysfs

	[ "$(board_name)" = 'tuoshi,lt22m' ] || return 74
	[ -r /proc/mtd ] || return 74
	for expected in \
		'0:u-boot:00030000:0:1' '1:u-boot-env:00010000:196608:1' \
		'2:factory:00010000:262144:0' '3:fwconcat0:00770000:327680:1' \
		'4:stock-storage:00040000:8126464:1' '5:fwconcat1:00050000:8388608:1' \
		'6:stock-firmware2:00770000:8716288:1' '7:fwconcat2:00040000:16515072:1'; do
		number="${expected%%:*}"
		part="${expected#*:}"; part="${part%%:*}"
		bytes="${expected#*:*:}"; bytes="${bytes%%:*}"
		offset="${expected#*:*:*:}"; offset="${offset%%:*}"
		writable="${expected##*:}"
		awk -v idx="mtd$number:" -v name="\"$part\"" -v size="$bytes" \
			'$1 == idx && $2 == size && $3 == "00010000" && $4 == name { found=1 }
			 END { exit !found }' /proc/mtd || return 74
		sysfs="/sys/class/mtd/mtd$number"
		[ "$(sed -n '1p' "$sysfs/offset" 2>/dev/null)" = "$offset" ] || return 74
		[ "$(sed -n '1p' "$sysfs/size" 2>/dev/null)" = "$((0x$bytes))" ] || return 74
		[ "$(sed -n '1p' "$sysfs/erasesize" 2>/dev/null)" = 65536 ] || return 74
		flags="$(sed -n '1p' "$sysfs/flags" 2>/dev/null)" || return 74
		case "$flags" in 0x[0-9a-fA-F]*) ;; *) return 74 ;; esac
		if [ "$writable" = 1 ]; then
			[ "$((flags & 0x400))" -ne 0 ] || return 74
		else
			[ "$((flags & 0x400))" -eq 0 ] || return 74
		fi
	done
	awk '$1 == "mtd8:" && $2 == "00800000" && $3 == "00010000" &&
		$4 == "\"firmware\"" { found=1 }
		END { exit !found }' /proc/mtd || return 74
	digest="$(sha256sum /dev/mtd0 2>/dev/null)" || return 74
	[ "${digest%% *}" = \
		'45eb1fbce7dbd5ede73054e5d1870c5e131f1cd8f0b641844889afae2421542b' ] || return 74
	[ "$(fw_printenv -n Image1Stable 2>/dev/null)" = 1 ] || return 74
	[ "$(fw_printenv -n Image1Try 2>/dev/null)" = 0 ] || return 74
}

lt22m_image_hex() {
	hexdump -v -s "$2" -n "$3" -e '4/1 "%02x"' "$1" 2>/dev/null
}

lt22m_image_le32() {
	hexdump -v -s "$2" -n 4 -e '1/4 "%u"' "$1" 2>/dev/null
}

# Verify the OEM kernel CRC and the external SquashFS superblock and bounds.
# The uImage CRC does not cover the complete SquashFS; these are structural
# checks, not a signature or checksum of all rootfs bytes. Repeat in stage 2.
lt22m_stock_check_image() {
	local image="$1" size kernel_hex kernel_bytes marker_offset marker
	local squash_inodes squash_block squash_used squash_high metadata supported board

	lt22m_stock_check_device || return 74
	[ -f "$image" ] && [ -r "$image" ] || return 74
	size="$(wc -c < "$image")" || return 74
	[ "$size" -gt 262144 ] && [ "$size" -le $((7104 * 1024)) ] || return 74
	[ "$(get_magic_long "$image")" = 27151967 ] || return 74
	[ "$(lt22m_image_hex "$image" 28 4)" = 05050203 ] || return 74
	[ "$(lt22m_image_hex "$image" 16 8)" = 8000000080000000 ] || return 74
	kernel_hex="$(lt22m_image_hex "$image" 12 4)" || return 74
	case "$kernel_hex" in ????????) ;; *) return 74 ;; esac
	kernel_bytes=$((0x$kernel_hex + 64))
	[ "$kernel_bytes" -gt 64 ] && [ "$kernel_bytes" -le $((0x770000)) ] || return 74
	[ "$((kernel_bytes + 96))" -le "$size" ] || return 74
	dumpimage -M 0x27151967 -l "$image" >/dev/null 2>&1 || return 74
	[ "$(lt22m_image_hex "$image" "$kernel_bytes" 4)" = 68737173 ] || return 74
	squash_inodes="$(lt22m_image_le32 "$image" "$((kernel_bytes + 4))")" || return 74
	squash_block="$(lt22m_image_le32 "$image" "$((kernel_bytes + 12))")" || return 74
	squash_used="$(lt22m_image_le32 "$image" "$((kernel_bytes + 40))")" || return 74
	squash_high="$(lt22m_image_le32 "$image" "$((kernel_bytes + 44))")" || return 74
	[ "$squash_inodes" -gt 0 ] && [ "$squash_high" -eq 0 ] || return 74
	[ "$squash_block" -ge 4096 ] && [ "$squash_block" -le 1048576 ] &&
		[ "$((squash_block & (squash_block - 1)))" -eq 0 ] || return 74
	[ "$(lt22m_image_hex "$image" "$((kernel_bytes + 28))" 4)" = 04000000 ] || return 74

	# mtd -j substitutes the aligned JFFS2 marker block with saved settings.
	marker_offset=$((size / 65536 * 65536))
	[ "$((marker_offset - kernel_bytes))" -ge 96 ] &&
		[ "$squash_used" -ge 96 ] &&
		[ "$squash_used" -le "$((marker_offset - kernel_bytes))" ] || return 74
	[ "$((size - marker_offset))" -ge 100 ] &&
		[ "$((size - marker_offset))" -le 4096 ] || return 74
	[ "$((marker_offset + 262144))" -le $((0x770000)) ] || return 74
	marker="$(lt22m_image_hex "$image" "$marker_offset" 4)" || return 74
	[ "$marker" = deadc0de ] || return 74
	metadata="$(fwtool -q -i - "$image" 2>/dev/null)" || return 74
	supported="$(printf '%s' "$metadata" | \
		jsonfilter -e '@.supported_devices[0]' 2>/dev/null)" || return 74
	board="$(printf '%s' "$metadata" | \
		jsonfilter -e '@.version.board' 2>/dev/null)" || return 74
	[ "$supported" = 'tuoshi,lt22m' ] && [ "$board" = tuoshi_lt22m ] || return 74
	if [ -n "$UPGRADE_BACKUP" ]; then
		[ -f "$UPGRADE_BACKUP" ] && [ -r "$UPGRADE_BACKUP" ] || return 74
		[ "$(wc -c < "$UPGRADE_BACKUP")" -le 262144 ] || return 74
		tar -tzf "$UPGRADE_BACKUP" >/dev/null 2>&1 || return 74
	fi
}

# Identify our SPL family by its bounded marker AND verify the entire
# second-stage uImage header and payload CRC. No fixed loader hash is needed.
lt22m_openwrt_loader() {
	local sample rc
	sample="$(mktemp /tmp/lt22m-loader.XXXXXX)" || return 74
	if dd if=/dev/mtd0 of="$sample" bs=65536 count=3 2>/dev/null &&
		[ "$(wc -c < "$sample")" -eq 196608 ] &&
		lt22m-image-check loader "$sample" >/dev/null 2>&1; then
		rc=0
	else
		rc=74
	fi
	rm -f "$sample"
	return "$rc"
}

lt22m_loader_kind() {
	if lt22m_openwrt_loader; then
		printf '%s\n' 'OpenWrt SPL family'
	elif [ "$(sha256sum /dev/mtd0 2>/dev/null | cut -d ' ' -f 1)" = \
		'45eb1fbce7dbd5ede73054e5d1870c5e131f1cd8f0b641844889afae2421542b' ]; then
		printf '%s\n' 'stock OEM'
	else
		printf '%s\n' unknown
	fi
}

lt22m_fullflash_loader_hint() {
	printf '%s\n' \
		'The LT22M "fullflash" image requires OpenWrt U-Boot bootloader.' \
		'Run lt22m-bootloader to flash the required bootloader.' >&2
}

lt22m_fullflash_stock_device() {
	local number entry sysfs flags
	[ "$(board_name)" = 'tuoshi,lt22m' ] || return 74
	[ -r /proc/mtd ] || return 74
	for entry in \
		'0:u-boot:00030000:0:1' '1:u-boot-env:00010000:196608:1' \
		'2:factory:00010000:262144:0' '3:fwconcat0:00770000:327680:1' \
		'4:stock-storage:00040000:8126464:1' '5:fwconcat1:00050000:8388608:1' \
		'6:stock-firmware2:00770000:8716288:1' '7:fwconcat2:00040000:16515072:1'; do
		number="${entry%%:*}"; entry="${entry#*:}"
		local name="${entry%%:*}"; entry="${entry#*:}"
		local bytes="${entry%%:*}"; entry="${entry#*:}"
		local offset="${entry%%:*}" writable="${entry##*:}"
		awk -v idx="mtd$number:" -v name="\"$name\"" -v size="$bytes" \
			'$1 == idx && $2 == size && $3 == "00010000" && $4 == name { n++ }
			 END { exit (n != 1) }' /proc/mtd || return 74
		sysfs="/sys/class/mtd/mtd$number"
		[ "$(sed -n '1p' "$sysfs/offset" 2>/dev/null)" = "$offset" ] || return 74
		[ "$(sed -n '1p' "$sysfs/size" 2>/dev/null)" = "$((0x$bytes))" ] || return 74
		[ "$(sed -n '1p' "$sysfs/erasesize" 2>/dev/null)" = 65536 ] || return 74
		flags="$(sed -n '1p' "$sysfs/flags" 2>/dev/null)" || return 74
		case "$flags" in 0x[0-9a-fA-F]*) ;; *) return 74 ;; esac
		if [ "$writable" = 1 ]; then
			[ "$((flags & 0x400))" -ne 0 ] || return 74
		else
			[ "$((flags & 0x400))" -eq 0 ] || return 74
		fi
	done
	awk '$1 == "mtd8:" && $2 == "00800000" && $3 == "00010000" &&
		$4 == "\"firmware\"" { n++ } END { exit (n != 1) }' /proc/mtd || return 74
	[ "$(sed -n '1p' /sys/class/mtd/mtd8/offset 2>/dev/null)" = 0 ] || return 74
	[ "$(sed -n '1p' /sys/class/mtd/mtd8/size 2>/dev/null)" = 8388608 ] || return 74
	[ "$(sed -n '1p' /sys/class/mtd/mtd8/erasesize 2>/dev/null)" = 65536 ] || return 74
	flags="$(sed -n '1p' /sys/class/mtd/mtd8/flags 2>/dev/null)" || return 74
	case "$flags" in 0x[0-9a-fA-F]*) ;; *) return 74 ;; esac
	[ "$((flags & 0x400))" -ne 0 ] || return 74
}

lt22m_fullflash_new_device() {
	local entry number name bytes offset writable sysfs flags
	[ "$(board_name)" = 'tuoshi,lt22m-fullflash' ] || return 74
	[ -r /proc/mtd ] || return 74
	for entry in '0:u-boot:00030000:0:1' \
		'1:u-boot-env:00010000:196608:1' '2:factory:00010000:262144:0' \
		'3:firmware:00fb0000:327680:1'; do
		number="${entry%%:*}"; entry="${entry#*:}"
		name="${entry%%:*}"; entry="${entry#*:}"
		bytes="${entry%%:*}"; entry="${entry#*:}"
		offset="${entry%%:*}"; writable="${entry##*:}"
		awk -v idx="mtd$number:" -v name="\"$name\"" -v size="$bytes" \
			'$1 == idx && $2 == size && $3 == "00010000" && $4 == name { n++ }
			 END { exit (n != 1) }' /proc/mtd || return 74
		sysfs="/sys/class/mtd/mtd$number"
		[ "$(sed -n '1p' "$sysfs/offset" 2>/dev/null)" = "$offset" ] || return 74
		[ "$(sed -n '1p' "$sysfs/size" 2>/dev/null)" = "$((0x$bytes))" ] || return 74
		[ "$(sed -n '1p' "$sysfs/erasesize" 2>/dev/null)" = 65536 ] || return 74
		flags="$(sed -n '1p' "$sysfs/flags" 2>/dev/null)" || return 74
		case "$flags" in 0x[0-9a-fA-F]*) ;; *) return 74 ;; esac
		if [ "$writable" = 1 ]; then
			[ "$((flags & 0x400))" -ne 0 ] || return 74
		else
			[ "$((flags & 0x400))" -eq 0 ] || return 74
		fi
	done
}

# The kernel data CRC ends at the uImage payload; the external squashfs and
# OpenWrt marker must be checked separately before any NOR access.
lt22m_fullflash_check_image() {
	local image="$1" size kernel_hex kernel_bytes marker_offset squash_inodes
	local squash_block squash_used squash_high metadata supported supported_next board
	[ -f "$image" ] && [ -r "$image" ] || return 74
	size="$(wc -c < "$image")" || return 74
	[ "$size" -gt 262144 ] && [ "$size" -le $((7104 * 1024)) ] || return 74
	[ "$(get_magic_long "$image")" = 27051956 ] || return 74
	[ "$(lt22m_image_hex "$image" 28 4)" = 05050203 ] || return 74
	[ "$(lt22m_image_hex "$image" 16 8)" = 8000000080000000 ] || return 74
	kernel_hex="$(lt22m_image_hex "$image" 12 4)" || return 74
	case "$kernel_hex" in
	????????) case "$kernel_hex" in *[!0123456789abcdefABCDEF]*) return 74 ;; esac ;;
	*) return 74 ;;
	esac
	kernel_bytes=$((0x$kernel_hex + 64))
	[ "$kernel_bytes" -gt 64 ] && [ "$((kernel_bytes + 96))" -le "$size" ] || return 74
	dumpimage -l "$image" >/dev/null 2>&1 || return 74
	[ "$(lt22m_image_hex "$image" "$kernel_bytes" 4)" = 68737173 ] || return 74
	squash_inodes="$(lt22m_image_le32 "$image" "$((kernel_bytes + 4))")" || return 74
	squash_block="$(lt22m_image_le32 "$image" "$((kernel_bytes + 12))")" || return 74
	squash_used="$(lt22m_image_le32 "$image" "$((kernel_bytes + 40))")" || return 74
	squash_high="$(lt22m_image_le32 "$image" "$((kernel_bytes + 44))")" || return 74
	[ "$squash_inodes" -gt 0 ] && [ "$squash_high" -eq 0 ] || return 74
	[ "$squash_block" -ge 4096 ] && [ "$squash_block" -le 1048576 ] &&
		[ "$((squash_block & (squash_block - 1)))" -eq 0 ] || return 74
	[ "$(lt22m_image_hex "$image" "$((kernel_bytes + 28))" 4)" = 04000000 ] || return 74
	marker_offset=$((size / 65536 * 65536))
	[ "$((marker_offset - kernel_bytes))" -ge 96 ] &&
		[ "$squash_used" -ge 96 ] &&
		[ "$squash_used" -le "$((marker_offset - kernel_bytes))" ] || return 74
	[ "$((size - marker_offset))" -ge 100 ] &&
		[ "$((size - marker_offset))" -le 4096 ] || return 74
	[ "$(lt22m_image_hex "$image" "$marker_offset" 4)" = deadc0de ] || return 74
	metadata="$(fwtool -q -i - "$image" 2>/dev/null)" || return 74
	supported="$(printf '%s' "$metadata" | \
		jsonfilter -e '@.supported_devices[0]' 2>/dev/null)" || return 74
	board="$(printf '%s' "$metadata" | \
		jsonfilter -e '@.version.board' 2>/dev/null)" || return 74
	supported_next="$(printf '%s' "$metadata" | \
		jsonfilter -e '@.supported_devices[1]' 2>/dev/null)" || return 74
	[ "$supported" = 'tuoshi,lt22m' ] &&
		[ "$supported_next" = 'tuoshi,lt22m-fullflash' ] &&
		[ "$board" = tuoshi_lt22m_fullflash ] || return 74
	if [ -n "${UPGRADE_BACKUP:-}" ]; then
		[ -f "$UPGRADE_BACKUP" ] && [ -r "$UPGRADE_BACKUP" ] || return 74
		[ "$(wc -c < "$UPGRADE_BACKUP")" -le 262144 ] || return 74
		tar -tzf "$UPGRADE_BACKUP" >/dev/null 2>&1 || return 74
	fi
}

lt22m_fullflash_migrate() {
	local image="$1" size next block ff pad padding before after part kind
	kind="$(lt22m_loader_kind)"
	echo "LT22M bootloader: $kind" >&2
	# mtd -j can expand the backup across an unbounded number of eraseblocks.
	# Migration writes only A: require -n rather than risk crossing its end.
	[ "$kind" = 'OpenWrt SPL family' ] || {
		lt22m_fullflash_loader_hint
		exit 74
	}
	[ -z "${UPGRADE_BACKUP:-}" ] && lt22m_fullflash_stock_device &&
		lt22m_fullflash_check_image "$image" || {
			echo 'LT22M: fullflash refused; check layout, image and sysupgrade -n.' >&2
			exit 74
		}
	before="$(sha256sum /dev/mtd0 /dev/mtd1 /dev/mtd2)" || exit 1
	size="$(wc -c < "$image")" || exit 1
	# mtd verify discards its comparison result and mtd erase discards ioctl
	# errors in this tree. Use write+readback, including every erased block.
	mtd write "$image" /dev/mtd3 || exit 1
	dd if=/dev/mtd3 bs=65536 count="$(((size + 65535) / 65536))" 2>/dev/null |
		head -c "$size" | cmp -s "$image" - || exit 1
	ff="$(mktemp /tmp/lt22m-ff.XXXXXX)" || exit 1
	dd if=/dev/zero bs=65536 count=1 2>/dev/null |
		tr '\000' '\377' > "$ff"
	if [ "$(wc -c < "$ff")" -ne 65536 ]; then
		rm -f "$ff"
		exit 1
	fi
	next=$(((size + 65535) / 65536))
	padding=$((next * 65536 - size))
	if [ "$padding" -gt 0 ]; then
		pad="$(mktemp /tmp/lt22m-pad.XXXXXX)" || exit 1
		head -c "$padding" "$ff" > "$pad" || exit 1
		dd if=/dev/mtd3 bs=1 skip="$size" count="$padding" 2>/dev/null |
			cmp -s "$pad" - || exit 1
		rm -f "$pad"
	fi
	while [ "$next" -lt 119 ]; do
		mtd -p "$((next * 65536))" write "$ff" /dev/mtd3 || exit 1
		dd if=/dev/mtd3 bs=65536 skip="$next" count=1 2>/dev/null |
			cmp -s "$ff" - || exit 1
		next=$((next + 1))
	done
	for part in 4 5 6 7; do
		mtd erase "/dev/mtd$part" || exit 1
		next=0
		case "$part" in 4|7) block=4 ;; 5) block=5 ;; 6) block=119 ;; esac
		while [ "$next" -lt "$block" ]; do
			dd if="/dev/mtd$part" bs=65536 skip="$next" count=1 2>/dev/null |
				cmp -s "$ff" - || exit 1
			next=$((next + 1))
		done
	done
	rm -f "$ff"
	after="$(sha256sum /dev/mtd0 /dev/mtd1 /dev/mtd2)" || exit 1
	[ "$before" = "$after" ] || exit 1
}

lt22m_image_board() {
	fwtool -q -i - "$1" 2>/dev/null | jsonfilter -e '@.version.board' 2>/dev/null
}

platform_check_image() {
	local image_board kind
	case "$(board_name)" in
		tuoshi,lt22m)
			image_board="$(lt22m_image_board "$1")" || return 74
			case "$image_board" in
			tuoshi_lt22m_fullflash)
				kind="$(lt22m_loader_kind)"
				echo "LT22M bootloader: $kind" >&2
				[ "$kind" = 'OpenWrt SPL family' ] || {
					lt22m_fullflash_loader_hint
					return 74
				}
				lt22m_fullflash_stock_device || {
					echo 'LT22M: stock MTD map is not transition-ready.' >&2
					return 74
				}
				# sysupgrade exports SAVE_CONFIG, but procd validates again in a
				# separate process without it. Mark this image as no-backup in
				# both checks; procd rejects a backup argument before any write.
				notify_firmware_no_backup
				[ -z "${SAVE_CONFIG+x}" ] || [ "$SAVE_CONFIG" = 0 ] || {
					echo 'LT22M: migration cannot preserve settings safely.' >&2
					echo 'Use sysupgrade -n.' >&2
					return 74
				}
				[ -z "${UPGRADE_BACKUP:-}" ] && [ -z "${CONF_IMAGE:-}" ] || {
					echo 'LT22M: migration cannot preserve settings safely.' >&2
					echo 'Use sysupgrade -n.' >&2
					return 74
				}
				lt22m_fullflash_check_image "$1" || {
					echo 'LT22M: unsafe fullflash image or settings backup.' >&2
					echo 'For migration, use sysupgrade -n.' >&2
					return 74
				}
				;;
			tuoshi_lt22m)
				lt22m_stock_check_image "$1" || {
					echo 'LT22M: unsafe stock loader, layout or image' >&2
					return 74
				}
				;;
			*) return 74 ;;
			esac
			;;
		tuoshi,lt22m-fullflash)
			kind="$(lt22m_loader_kind)"
			echo "LT22M bootloader: $kind" >&2
			[ "$kind" = 'OpenWrt SPL family' ] || {
				lt22m_fullflash_loader_hint
				return 74
			}
			lt22m_fullflash_new_device && lt22m_fullflash_check_image "$1" || {
				echo 'LT22M: unsafe fullflash layout or image.' >&2
				return 74
			}
			;;
	esac
	return 0
}

platform_do_upgrade() {
	local board=$(board_name) kind

	case "$board" in
	tuoshi,lt22m)
		# do_stage2 reboots after a normal return: terminate RAMFS on any
		# refusal, even when sysupgrade was invoked with -F.
		case "$(lt22m_image_board "$1")" in
		tuoshi_lt22m_fullflash)
			lt22m_fullflash_migrate "$1"
			;;
		tuoshi_lt22m)
			lt22m_stock_check_image "$1" || exit 74
			local protected_before protected_after size marker_offset
			protected_before="$(sha256sum /dev/mtd0 /dev/mtd1 /dev/mtd2 \
				/dev/mtd4 /dev/mtd6)" || exit 1
			default_do_upgrade "$1"
			# mtd -j replaces the aligned marker block with saved settings.
			# Verify the immutable kernel and SquashFS before that block.
			size="$(wc -c < "$1")" || exit 1
			marker_offset=$((size / 65536 * 65536))
			[ "$marker_offset" -gt 0 ] &&
				cmp -s -n "$marker_offset" "$1" /dev/mtd3 || {
					echo 'LT22M: slot A readback mismatch; refusing reboot' >&2
					exit 1
				}
			protected_after="$(sha256sum /dev/mtd0 /dev/mtd1 /dev/mtd2 \
				/dev/mtd4 /dev/mtd6)" || exit 1
			[ "$protected_before" = "$protected_after" ] || exit 1
			;;
		*) exit 74 ;;
		esac
		;;
	tuoshi,lt22m-fullflash)
		kind="$(lt22m_loader_kind)"
		echo "LT22M bootloader: $kind" >&2
		[ "$kind" = 'OpenWrt SPL family' ] || {
			lt22m_fullflash_loader_hint
			exit 74
		}
		lt22m_fullflash_new_device && lt22m_fullflash_check_image "$1" || exit 74
		default_do_upgrade "$1"
		;;
	alfa-network,awusfree1)
		[ "$(fw_printenv -n dual_image 2>/dev/null)" = "1" ] &&\
		[ -n "$(find_mtd_part backup)" ] && {
			PART_NAME=backup
			if [ "$(fw_printenv -n bootactive 2>/dev/null)" = "1" ]; then
				fw_setenv bootactive 2 || exit 1
			else
				fw_setenv bootactive 1 || exit 1
			fi
		}
		default_do_upgrade "$1"
		;;
	tplink,archer-c20-v5|\
	tplink,archer-c50-v4|\
	tplink,archer-c50-v6)
		MTD_ARGS="-t romfile"
		default_do_upgrade "$1"
		;;
	*)
		default_do_upgrade "$1"
		;;
	esac
}
