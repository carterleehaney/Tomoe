"""Unit tests for tomoe.cli — target expansion, file parsing, and argument parsing."""

import os

import pytest

from tomoe.cli import expand_target, parse_target_or_file, build_parser


class TestExpandTarget:
    def test_expand_target_single_ip(self):
        result = expand_target("192.168.1.1")
        assert result == ["192.168.1.1"]

    def test_expand_target_hostname(self):
        result = expand_target("myhost")
        assert result == ["myhost"]

    def test_expand_target_cidr_24(self):
        result = expand_target("10.0.0.0/24")
        assert len(result) == 254
        assert "10.0.0.1" in result
        assert "10.0.0.254" in result
        # Network and broadcast addresses are excluded by hosts()
        assert "10.0.0.0" not in result
        assert "10.0.0.255" not in result

    def test_expand_target_cidr_25(self):
        result = expand_target("10.0.0.0/25")
        assert len(result) == 126

    def test_expand_target_cidr_26(self):
        result = expand_target("10.0.0.0/26")
        assert len(result) == 62

    def test_expand_target_invalid_cidr(self):
        with pytest.raises(ValueError, match="only /24, /25, and /26"):
            expand_target("10.0.0.0/23")

    def test_expand_target_dash_range(self):
        result = expand_target("192.168.1.1-5")
        assert result == [
            "192.168.1.1",
            "192.168.1.2",
            "192.168.1.3",
            "192.168.1.4",
            "192.168.1.5",
        ]


class TestParseTargetOrFile:
    def test_parse_target_or_file_literal(self):
        result = parse_target_or_file("192.168.1.1")
        assert result == ["192.168.1.1"]

    def test_parse_target_or_file_from_file(self, tmp_path):
        target_file = tmp_path / "targets.txt"
        target_file.write_text("192.168.1.1\n192.168.1.2\nhostname\n")
        result = parse_target_or_file(str(target_file))
        assert result == ["192.168.1.1", "192.168.1.2", "hostname"]

    def test_parse_target_or_file_from_file_with_expansion(self, tmp_path):
        target_file = tmp_path / "targets.txt"
        target_file.write_text("192.168.1.1-3\n")
        result = parse_target_or_file(str(target_file))
        assert result == ["192.168.1.1", "192.168.1.2", "192.168.1.3"]

    def test_parse_target_or_file_no_expand(self, tmp_path):
        target_file = tmp_path / "users.txt"
        target_file.write_text("admin\nroot\n")
        result = parse_target_or_file(str(target_file), expand_entries=False)
        assert result == ["admin", "root"]


class TestBuildParser:
    def test_build_parser_smb_requires_password(self):
        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["smb", "192.168.1.1", "-u", "admin"])

    def test_build_parser_ssh_password_optional(self):
        parser = build_parser()
        args = parser.parse_args(["ssh", "192.168.1.1", "-u", "admin"])
        assert args.protocol == "ssh"
        assert args.password is None
        assert args.username == "admin"

    def test_build_parser_winrm_requires_password(self):
        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["winrm", "192.168.1.1", "-u", "admin"])

    def test_build_parser_smb_shell_default(self):
        parser = build_parser()
        args = parser.parse_args(["smb", "192.168.1.1", "-u", "admin", "-p", "pass", "-c", "whoami"])
        assert args.shell == "powershell"

    def test_build_parser_ssh_os_default(self):
        parser = build_parser()
        args = parser.parse_args(["ssh", "192.168.1.1", "-u", "admin", "-c", "whoami"])
        assert args.target_os == "windows"
