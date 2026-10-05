# SPDX-License-Identifier: GPL-2.0-only
"""Offline LT22M fullflash sysupgrade checks; never accesses host MTD."""

import os
import shlex
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


PLATFORM = (
    Path(__file__).resolve().parents[1]
    / "target/linux/ramips/mt76x8/base-files/lib/upgrade/platform.sh"
)


class FullflashUpgradeTests(unittest.TestCase):
    def run_shell(self, body, *, env=None):
        script = f'. "{PLATFORM}"\n' + body
        return subprocess.run(
            ["sh", "-c", script], capture_output=True, text=True,
            env={**os.environ, **(env or {})}, check=False,
        )

    def test_fullflash_image_limit_checked_before_parsing(self):
        with tempfile.TemporaryDirectory() as directory:
            oversized = Path(directory) / "oversized.bin"
            with oversized.open("wb") as output:
                output.truncate(7104 * 1024 + 1)
            result = self.run_shell(
                'get_magic_long() { echo "header was read" >&2; return 1; }\n'
                f'lt22m_fullflash_check_image "{oversized}"\n'
            )
            self.assertEqual(result.returncode, 74, result.stderr)
            self.assertNotIn("header was read", result.stderr)

    def test_fwtool_metadata_crc_covers_fullflash_rootfs(self):
        tree = PLATFORM.parents[7]
        image = (tree / 'bin/targets/ramips/mt76x8/'
                 'openwrt-ramips-mt76x8-tuoshi_lt22m_fullflash-squashfs-sysupgrade.bin')
        fwtool = tree / 'staging_dir/host/bin/fwtool'
        if not image.is_file() or not fwtool.is_file():
            self.skipTest('fullflash image and host fwtool must be built')
        original = image.read_bytes()
        self.assertEqual(subprocess.run([fwtool, '-q', '-i', '-', image],
                                        capture_output=True).returncode, 0)
        with tempfile.TemporaryDirectory() as directory:
            corrupt = Path(directory) / 'corrupt-rootfs.bin'
            data = bytearray(original)
            data[3000000] ^= 1  # SquashFS payload, outside uImage kernel CRC.
            corrupt.write_bytes(data)
            self.assertNotEqual(subprocess.run([fwtool, '-q', '-i', '-', corrupt],
                                               capture_output=True).returncode, 0)

    def test_stock_and_unknown_loader_refused_before_any_write(self):
        for kind in ("stock OEM", "unknown"):
            with self.subTest(kind=kind):
                mocks = (
                    'board_name() { echo "tuoshi,lt22m"; }\n'
                    'lt22m_image_board() { echo tuoshi_lt22m_fullflash; }\n'
                    f'lt22m_loader_kind() {{ echo "{kind}"; }}\n'
                    'lt22m_fullflash_stock_device() { echo "geometry checked" >&2; return 0; }\n'
                    'lt22m_fullflash_check_image() { echo "image checked" >&2; return 0; }\n'
                    'mtd() { echo "UNSAFE WRITE" >&2; return 0; }\n'
                    'default_do_upgrade() { echo "UNSAFE WRITE" >&2; return 0; }\n'
                )
                for action in ('platform_check_image fake.bin',
                               'platform_do_upgrade fake.bin'):
                    result = self.run_shell(mocks + action + '\n',
                                            env={'SAVE_CONFIG': '0',
                                                 'UPGRADE_BACKUP': ''})
                    self.assertEqual(result.returncode, 74, result.stderr)
                    self.assertIn(f'LT22M bootloader: {kind}', result.stderr)
                    self.assertIn('The LT22M "fullflash" image requires OpenWrt U-Boot bootloader.',
                                  result.stderr)
                    self.assertIn('Run lt22m-bootloader to flash the required bootloader.',
                                  result.stderr)
                    self.assertNotIn('UNSAFE WRITE', result.stderr)
                    self.assertNotIn('image checked', result.stderr)

    def test_spl_marker_without_valid_second_stage_is_not_accepted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            loader = root / 'mtd0'
            loader.write_bytes(b'LT22M_OPENWRT_UBOOT_FAMILY_V1'.ljust(196608, b'\xff'))
            checker = root / 'lt22m-image-check'
            source = (PLATFORM.parents[7] /
                      'package/utils/lt22m-bootloader/files/lt22m-image-check.c')
            subprocess.run(['cc', '-std=c99', '-O2', '-o', checker, source], check=True)
            script = PLATFORM.read_text().replace('/dev/mtd0', str(loader))
            for data, expected in ((loader.read_bytes(), 74),):
                loader.write_bytes(data)
                result = subprocess.run(
                    ['sh', '-c', script + '\nlt22m_openwrt_loader\n'],
                    capture_output=True, text=True,
                    env={**os.environ, 'PATH': f'{root}:{os.environ["PATH"]}'})
                self.assertEqual(result.returncode, expected)
            artifact = (PLATFORM.parents[7] /
                        'staging_dir/target-mipsel_24kc_musl/image/'
                        'mt7628_tuoshi_lt22m-u-boot-with-spl.bin')
            if artifact.is_file():
                loader.write_bytes(artifact.read_bytes().ljust(196608, b'\xff'))
                result = subprocess.run(
                    ['sh', '-c', script + '\nlt22m_openwrt_loader\n'],
                    capture_output=True, text=True,
                    env={**os.environ, 'PATH': f'{root}:{os.environ["PATH"]}'})
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_default_config_preservation_requires_explicit_no_settings(self):
        mocks = (
            'board_name() { echo "tuoshi,lt22m"; }\n'
            'lt22m_image_board() { echo tuoshi_lt22m_fullflash; }\n'
            'lt22m_loader_kind() { echo "OpenWrt SPL family"; }\n'
            'lt22m_fullflash_stock_device() { return 0; }\n'
            'lt22m_fullflash_check_image() { return 0; }\n'
            'notify_firmware_no_backup() { echo NO_BACKUP; }\n'
        )
        result = self.run_shell(mocks + 'platform_check_image fake.bin\n',
                                env={'SAVE_CONFIG': '1', 'UPGRADE_BACKUP': ''})
        self.assertEqual(result.returncode, 74, result.stderr)
        self.assertIn('sysupgrade -n', result.stderr)
        result = self.run_shell(mocks + 'platform_check_image fake.bin\n',
                                env={'SAVE_CONFIG': '0', 'UPGRADE_BACKUP': ''})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('NO_BACKUP', result.stdout)
        # procd runs the validator a second time without sysupgrade's -n env.
        procd_env = {k: v for k, v in os.environ.items()
                     if k not in ('SAVE_CONFIG', 'UPGRADE_BACKUP', 'CONF_IMAGE')}
        result = subprocess.run(
            ['sh', '-c', f'. "{PLATFORM}"\n' + mocks +
             'platform_check_image fake.bin\n'],
            env=procd_env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('NO_BACKUP', result.stdout)

    def test_migration_rejects_backup_even_with_openwrt_loader(self):
        mocks = (
            'board_name() { echo "tuoshi,lt22m"; }\n'
            'lt22m_image_board() { echo tuoshi_lt22m_fullflash; }\n'
            'lt22m_loader_kind() { echo "OpenWrt SPL family"; }\n'
            'lt22m_fullflash_stock_device() { return 0; }\n'
            'lt22m_fullflash_check_image() { return 0; }\n'
            'notify_firmware_no_backup() { echo NO_BACKUP; }\n'
            'mtd() { echo "UNSAFE WRITE" >&2; return 0; }\n'
        )
        for action in ('platform_check_image fake.bin',
                       'platform_do_upgrade fake.bin'):
            with self.subTest(action=action):
                result = self.run_shell(mocks + action + '\n',
                                        env={'UPGRADE_BACKUP': '/fake/backup.tgz'})
                self.assertEqual(result.returncode, 74, result.stderr)
                self.assertIn('sysupgrade -n', result.stderr)
                self.assertNotIn('UNSAFE WRITE', result.stderr)

    def run_fake_mtd_migration(self, directory, *, silent_erase=None):
        """Run the actual stage2 writer against regular files, never host MTD."""
        root = Path(directory)
        eraseblock = 65536
        sizes = (3, 1, 1, 119, 4, 5, 119, 4)
        devices = [root / f"mtd{part}" for part in range(8)]
        initial = []
        for part, (device, blocks) in enumerate(zip(devices, sizes)):
            data = bytes([0x31 + part]) * (blocks * eraseblock)
            device.write_bytes(data)
            initial.append(data)

        image = root / "image.bin"
        image_bytes = bytes(range(256)) * 1200 + b"non-aligned image tail"
        image.write_bytes(image_bytes)

        # Extract only the migration function: its /dev/mtd references are
        # replaced before a shell ever sees it. The real platform file is not
        # sourced, and the mock executable refuses any non-fixture destination.
        source = PLATFORM.read_text()
        function = ('lt22m_fullflash_migrate() {' + source.split(
            'lt22m_fullflash_migrate() {', 1)[1].split(
                '\nlt22m_image_board() {', 1)[0])
        self.assertIn('/dev/mtd3', function)
        function = function.replace('/dev/mtd', str(root / 'mtd'))
        self.assertNotIn('/dev/mtd', function)
        staged = root / 'migration.sh'
        staged.write_text(function)

        mock = root / 'mtd-bin' / 'mtd'
        mock.parent.mkdir()
        mock.write_text(textwrap.dedent('''\
            #!/usr/bin/env python3
            import os
            import sys
            from pathlib import Path

            root = Path(os.environ['MTD_FIXTURE_DIR'])
            args = sys.argv[1:]
            if len(args) < 2:
                sys.exit(2)
            target = Path(args[-1])
            if target.parent != root or target.name not in {f'mtd{i}' for i in range(3, 8)}:
                sys.exit(2)
            part = int(target.name[3:])
            block = 65536
            with open(os.environ['MTD_LOG'], 'a', encoding='ascii') as log:
                log.write(' '.join(args) + '\\n')
            if len(args) == 3 and args[0] == 'write' and part == 3:
                data = Path(args[1]).read_bytes()
                length = (len(data) + block - 1) // block * block
                if length > target.stat().st_size:
                    sys.exit(2)
                with target.open('r+b') as output:
                    output.write(data.ljust(length, b'\\xff'))
            elif len(args) == 5 and args[0] == '-p' and args[2] == 'write' and part == 3:
                offset = int(args[1])
                data = Path(args[3]).read_bytes()
                if offset % block or len(data) != block or offset + block > target.stat().st_size:
                    sys.exit(2)
                with target.open('r+b') as output:
                    output.seek(offset)
                    output.write(data)
            elif len(args) == 2 and args[0] == 'erase' and part in range(4, 8):
                # Model this tree's mtd erase returning success despite an
                # ioctl failure: no write, zero exit status.
                if str(part) != os.environ.get('MTD_SILENT_ERASE'):
                    target.write_bytes(b'\\xff' * target.stat().st_size)
            else:
                sys.exit(2)
        '''))
        mock.chmod(0o755)
        log = root / 'mtd.log'
        mocks = (
            'lt22m_loader_kind() { echo "OpenWrt SPL family"; }\n'
            'lt22m_fullflash_stock_device() { return 0; }\n'
            'lt22m_fullflash_check_image() { return 0; }\n'
        )
        command = (f'. {shlex.quote(str(staged))}\n' + mocks +
                   f'lt22m_fullflash_migrate {shlex.quote(str(image))}\n')
        env = {**os.environ, 'PATH': str(mock.parent) + os.pathsep + os.environ['PATH'],
               'MTD_FIXTURE_DIR': str(root), 'MTD_LOG': str(log),
               'MTD_SILENT_ERASE': str(silent_erase) if silent_erase else '',
               'UPGRADE_BACKUP': ''}
        result = subprocess.run(['sh', '-c', command], capture_output=True,
                                text=True, env=env, check=False)
        return result, devices, initial, image_bytes, log.read_text().splitlines()

    def test_migration_writes_image_and_erases_all_remaining_flash(self):
        with tempfile.TemporaryDirectory() as directory:
            result, devices, initial, image, commands = self.run_fake_mtd_migration(directory)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual([device.read_bytes() for device in devices[:3]], initial[:3])
            a = devices[3].read_bytes()
            self.assertEqual(a[:len(image)], image)
            self.assertEqual(a[len(image):], b'\xff' * (len(a) - len(image)))
            for part in range(4, 8):
                self.assertEqual(devices[part].read_bytes(),
                                 b'\xff' * len(initial[part]), f'mtd{part}')
            self.assertEqual(sum(command.startswith('-p ') for command in commands),
                             119 - (len(image) + 65535) // 65536)
            self.assertEqual([Path(command.split()[-1]).name for command in commands
                              if command.startswith('erase ')],
                             ['mtd4', 'mtd5', 'mtd6', 'mtd7'])

    def test_migration_rejects_silent_erase_before_next_partition(self):
        with tempfile.TemporaryDirectory() as directory:
            result, devices, initial, image, commands = self.run_fake_mtd_migration(
                directory, silent_erase=5)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertEqual([device.read_bytes() for device in devices[:3]], initial[:3])
            self.assertEqual(devices[3].read_bytes()[:len(image)], image)
            self.assertEqual(devices[4].read_bytes(), b'\xff' * len(initial[4]))
            self.assertEqual(devices[5].read_bytes(), initial[5])
            self.assertEqual(devices[6].read_bytes(), initial[6])
            self.assertEqual(devices[7].read_bytes(), initial[7])
            self.assertEqual([Path(command.split()[-1]).name for command in commands
                              if command.startswith('erase ')], ['mtd4', 'mtd5'])

    def test_fullflash_board_guards_normal_upgrade(self):
        mocks = (
            'board_name() { echo "tuoshi,lt22m-fullflash"; }\n'
            'lt22m_fullflash_new_device() { return 0; }\n'
            'lt22m_fullflash_check_image() { return 0; }\n'
            'default_do_upgrade() { echo "upgrade called"; }\n'
        )
        for kind, status in (("unknown", 74), ("OpenWrt SPL family", 0)):
            with self.subTest(kind=kind):
                result = self.run_shell(
                    mocks + f'lt22m_loader_kind() {{ echo "{kind}"; }}\n'
                    'platform_do_upgrade fake.bin\n'
                )
                self.assertEqual(result.returncode, status, result.stderr)
                self.assertEqual('upgrade called' in result.stdout,
                                 status == 0)
                if status == 74:
                    self.assertIn('The LT22M "fullflash" image requires OpenWrt U-Boot bootloader.',
                                  result.stderr)
                    self.assertIn('Run lt22m-bootloader to flash the required bootloader.',
                                  result.stderr)


if __name__ == '__main__':
    unittest.main()
