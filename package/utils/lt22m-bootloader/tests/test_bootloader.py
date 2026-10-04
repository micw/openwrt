#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Mock-MTD tests. No device access or hardware flash."""
import fcntl
import hashlib
import os
import pathlib
import pty
import resource
import subprocess
import tempfile
import termios
import unittest
import zlib

PKG = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = PKG / 'files/lt22m-bootloader'
CHECKER = PKG / 'files/lt22m-image-check.c'


def uimage(payload=b'kernel payload', magic=0x27151967, name=b'Linux kernel', loader=False):
    h = bytearray(64)
    h[0:4] = magic.to_bytes(4, 'big')
    h[12:16] = len(payload).to_bytes(4, 'big')
    h[16:20] = (0x80200000 if loader else 0x80000000).to_bytes(4, 'big')
    h[20:24] = (0x80200000 if loader else 0x802a8290).to_bytes(4, 'big')
    h[24:28] = zlib.crc32(payload).to_bytes(4, 'big')
    h[28:32] = b'\x11\x05\x01\x03' if loader else b'\x05\x05\x02\x03'
    h[32:32 + len(name)] = name
    h[4:8] = zlib.crc32(h).to_bytes(4, 'big')
    return bytes(h) + payload


class LoaderTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = pathlib.Path(temp.name)
        for path in ('bin', 'dev', 'sys/class/mtd'):
            (self.root / path).mkdir(parents=True)
        self.checker = self.root / 'bin/lt22m-image-check'
        subprocess.run(['gcc', '-std=c99', '-Wall', '-Wextra', '-Werror', '-O2',
                        '-o', str(self.checker), str(CHECKER)], check=True)
        self.loader = self.root / 'loader'
        self.loader.write_bytes(b'LT22M_OPENWRT_UBOOT_FAMILY_V1' + b'\xff' * 1024 +
                                uimage(b'U-Boot 2026.07-OpenWrt-LT22M', 0x27051956,
                                       loader=True))
        self.manifest = self.root / 'manifest'
        self.manifest.write_text(hashlib.sha256(self.loader.read_bytes()).hexdigest() + '\n')
        (self.root / 'dev/mtd0').write_bytes(bytes(196608))
        self.map(False)
        script = SCRIPT.read_text().replace('. /lib/functions.sh',
            'board_name() { echo "${TEST_BOARD:-tuoshi,lt22m}"; }')
        for a, b in {'/usr/share/lt22m/u-boot-with-spl.bin': str(self.loader),
                     '/usr/share/lt22m/bootloader.sha256': str(self.manifest),
                     '/usr/sbin/lt22m-image-check': str(self.checker),
                     '/proc/mtd': str(self.root / 'proc.mtd'),
                     '/sys/class/mtd/': str(self.root / 'sys/class/mtd') + '/',
                     '/dev/mtd': str(self.root / 'dev/mtd')}.items():
            script = script.replace(a, b)
        self.script = self.root / 'tool'
        self.script.write_text(script)
        self.log = self.root / 'mtd.log'
        writer = self.root / 'bin/mtd'
        writer.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$MTD_LOG"\n'
                          'test "$1" = write && test "$3" = u-boot || exit 1\n'
                          'cp "$2" "$FAKE_MTD0"\n')
        writer.chmod(0o755)
        self.env = {**os.environ, 'PATH': str(self.root / 'bin') + ':' + os.environ['PATH'],
                    'MTD_LOG': str(self.log), 'FAKE_MTD0': str(self.root / 'dev/mtd0')}

    def map(self, full):
        common = [(0, 'u-boot', 0x30000, 0, True),
                  (1, 'u-boot-env', 0x10000, 0x30000, True),
                  (2, 'factory', 0x10000, 0x40000, False)]
        tail = ([(3, 'firmware', 0xfb0000, 0x50000, True)] if full else
                [(3, 'fwconcat0', 0x770000, 0x50000, True),
                 (4, 'stock-storage', 0x40000, 0x7c0000, True),
                 (5, 'fwconcat1', 0x50000, 0x800000, True),
                 (6, 'stock-firmware2', 0x770000, 0x850000, True),
                 (7, 'fwconcat2', 0x40000, 0xfc0000, True),
                 (8, 'firmware', 0x800000, 0x50000, True)])
        with (self.root / 'proc.mtd').open('w') as f:
            for n, name, size, offset, writable in common + tail:
                f.write(f'mtd{n}: {size:08x} 00010000 "{name}"\n')
                sys = self.root / f'sys/class/mtd/mtd{n}'
                sys.mkdir(exist_ok=True)
                for key, value in [('offset', offset), ('size', size),
                                   ('erasesize', 65536), ('flags', '0x400' if writable else '0x0')]:
                    (sys / key).write_text(str(value) + '\n')
        if full:
            image = bytearray(b'\xff' * 0xfb0000)
            image[:80] = uimage()[:80]
            image[0x800000:0x800050] = uimage(b'kernel payload B')[:80]
            (self.root / 'dev/mtd3').write_bytes(image)
        else:
            for n in (3, 6):
                (self.root / f'dev/mtd{n}').write_bytes(uimage().ljust(0x770000, b'\xff'))

    def run_tool(self, *args, full=False):
        env = {**self.env, 'TEST_BOARD': 'tuoshi,lt22m-fullflash' if full else 'tuoshi,lt22m'}
        return subprocess.run(['/bin/sh', str(self.script), *map(str, args)], env=env,
                              capture_output=True, text=True)

    def no_write(self):
        self.assertFalse(self.log.exists(), 'unexpected MTD write')

    def test_staged_binary_crc(self):
        artifact = SCRIPT.parents[4] / ('staging_dir/target-mipsel_24kc_musl/image/'
                                         'mt7628_tuoshi_lt22m-u-boot-with-spl.bin')
        if artifact.exists():
            self.assertEqual(subprocess.run([self.checker, 'loader', artifact]).returncode, 0)
            broken = self.root / 'broken'
            raw = bytearray(artifact.read_bytes()); raw[-1] ^= 1
            broken.write_bytes(raw)
            self.assertNotEqual(subprocess.run([self.checker, 'loader', broken]).returncode, 0)

    def test_inspect_scans_both_slots_and_unknown_skips(self):
        # Kernel/rootfs/rootfs_data are additional derived MTDs on real LT22M.
        with (self.root / 'proc.mtd').open('a') as mtd:
            for n, name in ((9, 'kernel'), (10, 'rootfs'), (11, 'rootfs_data')):
                mtd.write(f'mtd{n}: 00010000 00010000 "{name}"\n')
        (self.root / 'dev/mtd0').write_bytes(self.loader.read_bytes().ljust(196608, b'\xff'))
        result = self.run_tool('inspect')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('A at 0x050000: OEM MIPS Linux/LZMA uImage; header CRC OK; payload CRC OK', result.stdout)
        self.assertIn('B at 0x850000: OEM MIPS Linux/LZMA uImage; header CRC OK; payload CRC OK', result.stdout)
        self.assertIn('Compatibility: COMPATIBLE with current image in A', result.stdout)
        (self.root / 'dev/mtd6').write_bytes(b'?' * 0x770000)
        self.assertIn('B at 0x850000: no recognized OEM or standard uImage header',
                      self.run_tool('inspect').stdout)
        (self.root / 'dev/mtd0').write_bytes(bytes(196608))
        self.assertNotIn('A at 0x050000:', self.run_tool('inspect').stdout)
        self.no_write()

    def test_fullflash_physical_b_and_geometry(self):
        self.map(True)
        (self.root / 'dev/mtd0').write_bytes(self.loader.read_bytes().ljust(196608, b'\xff'))
        r = self.run_tool('inspect', full=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('B at 0x850000 (former stock slot): OEM MIPS Linux/LZMA uImage; header CRC OK; payload CRC OK', r.stdout)
        with (self.root / 'dev/mtd3').open('r+b') as f:
            f.seek(0x800000 + 65); f.write(b'!')
        self.assertIn('B at 0x850000 (former stock slot): uImage payload CRC FAIL',
                      self.run_tool('inspect', full=True).stdout)
        (self.root / 'sys/class/mtd/mtd2/flags').write_text('0x400\n')
        self.assertIn('mtd2 not protected', self.run_tool('inspect', full=True).stderr)
        self.no_write()

    def test_slot_crc_streams_without_large_allocation(self):
        self.map(True)
        device = self.root / 'dev/mtd3'
        kernel = uimage(b'k' * (0x770000 - 64), magic=0x27051956)
        with device.open('r+b') as mtd:
            mtd.seek(0)
            mtd.write(kernel)

        def limit_memory():
            resource.setrlimit(resource.RLIMIT_AS, (8 * 1024 * 1024,
                                                    8 * 1024 * 1024))

        result = subprocess.run([self.checker, 'slot', device, '0', str(0x770000)],
                                capture_output=True, text=True,
                                preexec_fn=limit_memory)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('standard MIPS Linux/LZMA uImage; header CRC OK; '
                      'payload CRC OK', result.stdout)
        for offset, size in (('-1', '7798784'), ('0', '42949672960'),
                             (str(0x800000), str(0x800000))):
            with self.subTest(offset=offset, size=size):
                result = subprocess.run([self.checker, 'slot', device, offset, size],
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode, 2)

        # B's declared payload must fit the 0x770000 slot, not the larger
        # remaining area of the fullflash MTD.
        oversized = bytearray(uimage())
        oversized[12:16] = (0x770000 - 63).to_bytes(4, 'big')
        with device.open('r+b') as mtd:
            mtd.seek(0x800000)
            mtd.write(oversized)
        result = subprocess.run([self.checker, 'slot', device, str(0x800000),
                                 str(0x770000)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn('outside the slot', result.stdout)

    def test_dump_identifies_without_slots(self):
        # Dump must also work on an older running stock DTS with B/storage RO.
        for n in (4, 6):
            (self.root / f'sys/class/mtd/mtd{n}/flags').write_text('0x0\n')
        target = self.root / 'dump'
        r = self.run_tool('dump', target)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('UNKNOWN bootloader - compatibility cannot be determined', r.stdout)
        self.assertNotIn('A at 0x050000:', r.stdout)
        self.assertEqual(len(target.read_bytes()), 196608)
        self.no_write()

    def test_stock_candidate_invalid_b_warns_not_blocks(self):
        # Stock fingerprint is known even though proprietary bytes are not in fixtures.
        source = self.root / 'stock'
        source.write_bytes(bytes(196608))
        sha = self.root / 'bin/sha256sum'
        sha.write_text('#!/bin/sh\ncase "$1" in */candidate) '
                       'echo "45eb1fbce7dbd5ede73054e5d1870c5e131f1cd8f0b641844889afae2421542b  $1";; '
                       '*) exec /usr/bin/sha256sum "$@";; esac\n')
        sha.chmod(0o755)
        (self.root / 'dev/mtd6').write_bytes(b'?' * 0x770000)
        r = self.run_tool('flash', source)
        self.assertIn('Compatibility: COMPATIBLE with current image in A', r.stdout)
        self.assertIn('WARNING: No stock-bootable fallback image in B.', r.stdout)
        self.assertNotIn('WARNING: No stock-bootable image in A.', r.stdout)
        self.assertNotIn('system will probably not boot', r.stdout)
        self.assertIn('interactive terminal required', r.stderr)
        self.no_write()

    def test_stock_candidate_on_fullflash_reports_magic_and_warning_last(self):
        self.map(True)
        image = bytearray(b'\xff' * 0xfb0000)
        kernel = uimage(magic=0x27051956)
        image[:len(kernel)] = kernel
        (self.root / 'dev/mtd3').write_bytes(image)
        source = self.root / 'stock'
        source.write_bytes(bytes(196608))
        sha = self.root / 'bin/sha256sum'
        sha.write_text('#!/bin/sh\ncase "$1" in */candidate) '
                       'echo "45eb1fbce7dbd5ede73054e5d1870c5e131f1cd8f0b641844889afae2421542b  $1";; '
                       '*) exec /usr/bin/sha256sum "$@";; esac\n')
        sha.chmod(0o755)
        result = self.run_tool('flash', source, full=True)
        self.assertIn('A at 0x050000: standard MIPS Linux/LZMA uImage; '
                      'header CRC OK; payload CRC OK', result.stdout)
        self.assertIn('Compatibility: NOT COMPATIBLE - no stock-bootable image in A or B',
                      result.stdout)
        self.assertIn('A has valid CRCs, but the stock bootloader rejects standard uImage magic',
                      result.stdout)
        self.assertIn('WARNING: No stock-bootable image in A.\n'
                      'WARNING: No stock-bootable fallback image in B.\n'
                      'WARNING: With this stock bootloader, the system will probably not boot.',
                      result.stdout)
        self.assertIn('B at 0x850000 (former stock slot): '
                      'no recognized OEM or standard uImage header', result.stdout)
        self.assertLess(result.stdout.index('B at 0x850000'),
                        result.stdout.index('Compatibility: NOT COMPATIBLE'))
        self.assertLess(result.stdout.index('Compatibility: NOT COMPATIBLE'),
                        result.stdout.index('WARNING: No stock-bootable fallback image in B.'))
        self.assertIn('\nWARNING: No stock-bootable fallback image in B.', result.stdout)
        self.assertIn('\nPlanned write:', result.stdout)
        self.assertIn('Type YES to flash the bootloader now:', result.stdout)
        self.no_write()

    def test_stock_loader_boots_one_valid_fallback_image(self):
        self.map(True)
        source = self.root / 'stock'
        source.write_bytes(bytes(196608))
        sha = self.root / 'bin/sha256sum'
        sha.write_text('#!/bin/sh\ncase "$1" in */candidate) '
                       'echo "45eb1fbce7dbd5ede73054e5d1870c5e131f1cd8f0b641844889afae2421542b  $1";; '
                       '*) exec /usr/bin/sha256sum "$@";; esac\n')
        sha.chmod(0o755)
        image = bytearray(b'\xff' * 0xfb0000)
        kernel = uimage(magic=0x27151967)
        image[0x800000:0x800000 + len(kernel)] = kernel
        (self.root / 'dev/mtd3').write_bytes(image)
        result = self.run_tool('flash', source, full=True)
        self.assertIn('Compatibility: COMPATIBLE via fallback image in B', result.stdout)
        self.assertIn('B at 0x850000 (former stock slot): OEM MIPS', result.stdout)
        self.assertIn('WARNING: No stock-bootable image in A.', result.stdout)
        self.assertNotIn('system will probably not boot', result.stdout)

        standard = uimage(magic=0x27051956)
        image[:len(standard)] = standard
        image[0x800000:0x800000 + len(standard)] = standard
        (self.root / 'dev/mtd3').write_bytes(image)
        result = self.run_tool('flash', source, full=True)
        self.assertIn('Compatibility: NOT COMPATIBLE - no stock-bootable image in A or B',
                      result.stdout)
        self.assertIn('B has valid CRCs, but the stock bootloader rejects standard uImage magic',
                      result.stdout)
        self.assertIn('WARNING: No stock-bootable image in A.\n'
                      'WARNING: No stock-bootable fallback image in B.\n'
                      'WARNING: With this stock bootloader, the system will probably not boot.',
                      result.stdout)

        image[0x800000:0x800000 + len(standard)] = b'\xff' * len(standard)
        (self.root / 'dev/mtd3').write_bytes(image)
        result = self.run_tool('flash', source, full=True)
        self.assertIn('Compatibility: NOT COMPATIBLE - no stock-bootable image in A or B',
                      result.stdout)
        self.no_write()

    def confirmed(self, answer, source):
        master, slave = pty.openpty()
        try:
            def terminal():
                os.setsid()
                fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
            p = subprocess.Popen(['/bin/sh', str(self.script), 'flash', str(source)],
                                 stdin=slave, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 text=True, env=self.env, preexec_fn=terminal)
            os.close(slave); slave = -1
            os.write(master, answer.encode() + b'\n')
            out, err = p.communicate(timeout=30)
            return p.returncode, out, err
        finally:
            os.close(master)
            if slave >= 0: os.close(slave)

    def test_confirmation_exact_and_full_readback(self):
        source = self.root / 'unknown'
        source.write_bytes(b'operator image')
        code, out, err = self.confirmed('NO', source)
        self.assertNotEqual(code, 0)
        self.no_write()
        code, out, err = self.confirmed('YES', source)
        self.assertEqual(code, 0, err)
        self.assertIn('Readback: OK - all 196608 bytes match', out)
        self.assertEqual((self.root / 'dev/mtd0').read_bytes(),
                         source.read_bytes().ljust(196608, b'\xff'))
        self.assertEqual(self.log.read_text().strip().split()[-1], 'u-boot')

    def test_readback_mismatch_and_wrong_geometry(self):
        source = self.root / 'unknown'
        source.write_bytes(b'operator image')
        (self.root / 'sys/class/mtd/mtd0/size').write_text('65536\n')
        r = self.run_tool('flash', source)
        self.assertIn('mtd0 size', r.stderr)
        self.no_write()
        (self.root / 'sys/class/mtd/mtd0/size').write_text('196608\n')
        writer = self.root / 'bin/mtd'
        writer.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$MTD_LOG"\nexit 0\n')
        writer.chmod(0o755)
        code, out, err = self.confirmed('YES', source)
        self.assertNotEqual(code, 0)
        self.assertIn('readback mismatch; do not reboot', err)
        self.assertNotIn('Readback: OK', out)

    def test_crc_rejects_corrupted_header_and_payload(self):
        valid = bytearray(self.loader.read_bytes())
        for index in (len(valid) - 1, len(b'LT22M_OPENWRT_UBOOT_FAMILY_V1') + 1024 + 5):
            bad = valid[:]; bad[index] ^= 1
            file = self.root / 'corrupt'; file.write_bytes(bad)
            self.assertNotEqual(subprocess.run([self.checker, 'loader', file]).returncode, 0)
        self.no_write()


if __name__ == '__main__':
    unittest.main()
