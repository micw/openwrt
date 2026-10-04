// SPDX-License-Identifier: GPL-2.0-only
/* Bounded LT22M SPL marker and uImage header/payload CRC inspection. */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_IMAGE 8388608U
#define LOADER_SIZE 196608U
#define SPL_LIMIT 65536U

static const unsigned char marker[] = "LT22M_OPENWRT_UBOOT_FAMILY_V1";

static uint32_t be32(const unsigned char *p)
{
	return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 |
	       (uint32_t)p[2] << 8 | p[3];
}

static uint32_t crc32_update(uint32_t crc, const unsigned char *p, size_t n)
{
	while (n--) {
		crc ^= *p++;
		for (int j = 0; j < 8; j++)
			crc = (crc >> 1) ^ (0xedb88320U & -(crc & 1U));
	}
	return crc;
}

static uint32_t crc32(const unsigned char *p, size_t n)
{
	return ~crc32_update(~0U, p, n);
}

/* 0: no recognized header; 1: valid; negative: reason for rejection. */
static int check_image(const unsigned char *data, size_t size, size_t offset,
		       int firmware)
{
	unsigned char hdr[64];
	uint32_t len, load, entry;

	if (offset > size || size - offset < sizeof(hdr))
		return 0;
	memcpy(hdr, data + offset, sizeof(hdr));
	if (be32(hdr) != (firmware ? 0x27151967U : 0x27051956U) &&
	    (!firmware || be32(hdr) != 0x27051956U))
		return 0;

	len = be32(hdr + 12);
	if (!len || len > size - offset - sizeof(hdr))
		return -1;
	memset(hdr + 4, 0, 4);
	if (crc32(hdr, sizeof(hdr)) != be32(data + offset + 4))
		return -2;
	if (crc32(data + offset + 64, len) != be32(data + offset + 24))
		return -3;

	load = be32(data + offset + 16);
	entry = be32(data + offset + 20);
	if (firmware) {
		if (memcmp(data + offset + 28, "\005\005\002\003", 4) ||
		    load != 0x80000000U ||
		    (entry != 0x80000000U && entry != 0x802a8290U))
			return -4;
	} else if (memcmp(data + offset + 28, "\021\005\001\003", 4) ||
		   load != 0x80200000U || entry != 0x80200000U) {
		return -4;
	}
	return 1;
}

static void loader_version(const unsigned char *data, size_t size)
{
	static const char prefix[] = "U-Boot ";
	size_t limit = size < SPL_LIMIT ? size : SPL_LIMIT;

	for (size_t i = 0; i + sizeof(prefix) < limit; i++) {
		size_t j = i + sizeof(prefix) - 1;

		if (memcmp(data + i, prefix, sizeof(prefix) - 1) ||
		    data[j] < '0' || data[j] > '9')
			continue;
		while (j < limit && j - i < 63 && data[j] > ' ' &&
		       data[j] < 127)
			j++;
		printf("%.*s\n", (int)(j - i), data + i);
		return;
	}
	puts("version unknown");
}

static int check_loader(const unsigned char *data, size_t size)
{
	size_t m, i;

	if (size > LOADER_SIZE)
		return 1;
	for (m = 0; m + sizeof(marker) - 1 <= size &&
	     m + sizeof(marker) - 1 <= SPL_LIMIT; m++) {
		if (!memcmp(data + m, marker, sizeof(marker) - 1))
			break;
	}
	if (m + sizeof(marker) - 1 > size ||
	    m + sizeof(marker) - 1 > SPL_LIMIT)
		return 1;

	for (i = m + sizeof(marker) - 1; i + 64 <= size; i++) {
		if (check_image(data, size, i, 0) == 1) {
			puts("LT22M OpenWrt U-Boot (family marker and second-stage CRC valid)");
			loader_version(data, size);
			return 0;
		}
	}
	return 1;
}

/* The slot may be 7.4 MiB; validate its kernel without copying the slot. */
static int check_slot(FILE *file, size_t offset, size_t slot_size)
{
	unsigned char hdr[64], checked[64], chunk[4096];
	uint32_t len, load, entry, crc;
	size_t remaining, count;
	char name[33];
	int result = -5;

	if (slot_size < sizeof(hdr) || fseek(file, (long)offset, SEEK_SET) ||
	    fread(hdr, 1, sizeof(hdr), file) != sizeof(hdr))
		goto report;
	if (be32(hdr) != 0x27151967U && be32(hdr) != 0x27051956U) {
		result = 0;
		goto report;
	}
	len = be32(hdr + 12);
	if (!len || len > slot_size - sizeof(hdr)) {
		result = -1;
		goto report;
	}
	memcpy(checked, hdr, sizeof(checked));
	memset(checked + 4, 0, 4);
	if (crc32(checked, sizeof(checked)) != be32(hdr + 4)) {
		result = -2;
		goto report;
	}
	crc = ~0U;
	remaining = len;
	while (remaining) {
		count = remaining < sizeof(chunk) ? remaining : sizeof(chunk);
		if (fread(chunk, 1, count, file) != count)
			goto report;
		crc = crc32_update(crc, chunk, count);
		remaining -= count;
	}
	if (~crc != be32(hdr + 24)) {
		result = -3;
		goto report;
	}
	load = be32(hdr + 16);
	entry = be32(hdr + 20);
	if (memcmp(hdr + 28, "\005\005\002\003", 4) ||
	    load != 0x80000000U ||
	    (entry != 0x80000000U && entry != 0x802a8290U)) {
		result = -4;
		goto report;
	}
	result = 1;

report:
	if (result == 1) {
		memcpy(name, hdr + 32, 32);
		name[32] = 0;
		for (int i = 0; i < 32; i++) {
			if ((unsigned char)name[i] < 32 ||
			    (unsigned char)name[i] > 126)
				name[i] = 0;
		}
		printf("%s MIPS Linux/LZMA uImage; header CRC OK; payload CRC OK; name: %s\n",
		       be32(hdr) == 0x27151967U ? "OEM" : "standard", name);
	} else if (result == -1) {
		puts("uImage payload size is outside the slot");
	} else if (result == -2) {
		puts("uImage header CRC FAIL");
	} else if (result == -3) {
		puts("uImage payload CRC FAIL");
	} else if (result == -4) {
		puts("uImage CRC OK; incompatible kernel type or load address");
	} else if (result == -5) {
		puts("slot read error");
	} else {
		puts("no recognized OEM or standard uImage header");
	}
	return result == 1 ? 0 : 1;
}

int main(int argc, char **argv)
{
	FILE *file;
	unsigned char *data;
	long length;
	unsigned long offset, slot_size;
	char *end;
	int result;

	/* One loader or a physical slot with its explicit size bound. */
	if (!((argc == 3 && !strcmp(argv[1], "loader")) ||
	      (argc == 5 && !strcmp(argv[1], "slot"))))
		return 2;

	file = fopen(argv[2], "rb");
	if (!file)
		return 1;
	if (fseek(file, 0, SEEK_END)) {
		fclose(file);
		return 1;
	}
	length = ftell(file);
	if (length < 0) {
		fclose(file);
		return 1;
	}

	if (!strcmp(argv[1], "slot")) {
		errno = 0;
		offset = strtoul(argv[3], &end, 0);
		if (errno || end == argv[3] || *end || argv[3][0] == '-') {
			fclose(file);
			return 2;
		}
		errno = 0;
		slot_size = strtoul(argv[4], &end, 0);
		if (errno || end == argv[4] || *end || argv[4][0] == '-' ||
		    !slot_size || slot_size > MAX_IMAGE ||
		    offset > (unsigned long)length ||
		    slot_size > (unsigned long)length - offset) {
			fclose(file);
			return 2;
		}
		result = check_slot(file, offset, slot_size);
		fclose(file);
		return result;
	}

	if ((unsigned long)length > LOADER_SIZE || fseek(file, 0, SEEK_SET)) {
		fclose(file);
		return 1;
	}
	data = malloc(length ? (size_t)length : 1);
	if (!data) {
		fclose(file);
		return 1;
	}
	if (fread(data, 1, length, file) != (size_t)length) {
		free(data);
		fclose(file);
		return 1;
	}
	fclose(file);
	result = check_loader(data, length);
	free(data);
	return result;
}
