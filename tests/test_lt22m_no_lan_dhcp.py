# SPDX-License-Identifier: GPL-2.0-only
"""Offline first-boot DHCP policy tests; no device access."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = (Path(__file__).resolve().parents[1] /
          'target/linux/ramips/mt76x8/base-files/etc/uci-defaults/'
          '97_lt22m_fullflash_no_lan_dhcp')


class FullflashDhcpDefaults(unittest.TestCase):
    def run_script(self, board, fail_commit=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log = root / 'uci.log'
            script = SCRIPT.read_text().replace(
                '. /lib/functions.sh', f'board_name() {{ echo "{board}"; }}')
            wrapper = root / 'run.sh'
            wrapper.write_text('uci() { printf "%s\\n" "$*" >> "$UCI_LOG"; '
                               '[ "$FAIL_COMMIT" != 1 ] || [ "$1" != commit ]; }\n'
                               + script)
            result = subprocess.run(
                ['sh', str(wrapper)], capture_output=True, text=True,
                env={**os.environ, 'UCI_LOG': str(log),
                     'FAIL_COMMIT': '1' if fail_commit else '0'})
            return result, log.read_text().splitlines() if log.exists() else []

    def test_fullflash_disables_only_lan_address_services(self):
        result, calls = self.run_script('tuoshi,lt22m-fullflash')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls, [
            '-q set dhcp.lan.ignore=1',
            '-q set dhcp.lan.dhcpv4=disabled',
            '-q set dhcp.lan.dhcpv6=disabled',
            '-q set dhcp.lan.ra=disabled',
            '-q set dhcp.lan.ndp=disabled',
            'commit dhcp',
        ])

    def test_stock_and_unrelated_boards_remain_unchanged(self):
        for board in ('tuoshi,lt22m', 'other,board'):
            with self.subTest(board=board):
                result, calls = self.run_script(board)
                self.assertEqual(result.returncode, 0)
                self.assertEqual(calls, [])

    def test_failed_commit_does_not_report_success(self):
        result, calls = self.run_script('tuoshi,lt22m-fullflash', fail_commit=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(calls[-1], 'commit dhcp')


if __name__ == '__main__':
    unittest.main()
