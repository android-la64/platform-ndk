#!/usr/bin/env python3
#
# Copyright (C) 2019 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
"""Unittests for ndk-stack.py"""
import textwrap
import unittest
from io import StringIO
from pathlib import Path, PurePosixPath
from typing import Any
from unittest import mock
from unittest.mock import Mock, patch

import pytest

import ndkstack


class TestFindLlvmSymbolizer:
    def test_find_in_prebuilt(self, tmp_path: Path) -> None:
        ndk_path = tmp_path / "ndk"
        symbolizer_path = (
            ndk_path / "toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-symbolizer"
        )
        symbolizer_path = symbolizer_path.with_suffix(ndkstack.EXE_SUFFIX)
        symbolizer_path.parent.mkdir(parents=True)
        symbolizer_path.touch()
        assert (
            ndkstack.find_llvm_symbolizer(ndk_path, ndk_path / "bin", "linux-x86_64")
            == symbolizer_path
        )

    def test_find_in_standalone_toolchain(self, tmp_path: Path) -> None:
        ndk_path = tmp_path / "ndk"
        symbolizer_path = ndk_path / "bin/llvm-symbolizer"
        symbolizer_path = symbolizer_path.with_suffix(ndkstack.EXE_SUFFIX)
        symbolizer_path.parent.mkdir(parents=True)
        symbolizer_path.touch()
        assert (
            ndkstack.find_llvm_symbolizer(ndk_path, ndk_path / "bin", "linux-x86_64")
            == symbolizer_path
        )

    def test_not_found(self, tmp_path: Path) -> None:
        with pytest.raises(OSError, match="Unable to find llvm-symbolizer"):
            ndkstack.find_llvm_symbolizer(tmp_path, tmp_path / "bin", "linux-x86_64")


class TestFindReadelf:
    def test_find_in_prebuilt(self, tmp_path: Path) -> None:
        ndk_path = tmp_path / "ndk"
        readelf_path = (
            ndk_path / "toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-readelf"
        )
        readelf_path = readelf_path.with_suffix(ndkstack.EXE_SUFFIX)
        readelf_path.parent.mkdir(parents=True)
        readelf_path.touch()
        assert (
            ndkstack.find_readelf(ndk_path, ndk_path / "bin", "linux-x86_64")
            == readelf_path
        )

    def test_find_in_standalone_toolchain(self, tmp_path: Path) -> None:
        ndk_path = tmp_path / "ndk"
        readelf_path = ndk_path / "bin/llvm-readelf"
        readelf_path = readelf_path.with_suffix(ndkstack.EXE_SUFFIX)
        readelf_path.parent.mkdir(parents=True)
        readelf_path.touch()
        assert (
            ndkstack.find_readelf(ndk_path, ndk_path / "bin", "linux-x86_64")
            == readelf_path
        )

    def test_not_found(self, tmp_path: Path) -> None:
        assert ndkstack.find_readelf(tmp_path, tmp_path / "bin", "linux-x86_64") is None


class FrameTests(unittest.TestCase):
    """Test parsing of backtrace lines."""

    def test_line_with_map_name(self) -> None:
        line = b"  #14 pc 00001000  /fake/libfake.so"
        frame_info = ndkstack.FrameInfo.from_line(line)
        assert frame_info is not None
        self.assertEqual(b"#14", frame_info.num)
        self.assertEqual(b"00001000", frame_info.pc)
        self.assertEqual(b"/fake/libfake.so", frame_info.tail)
        self.assertEqual(PurePosixPath("/fake/libfake.so"), frame_info.elf_file)
        self.assertFalse(frame_info.offset)
        self.assertFalse(frame_info.container_file)
        self.assertFalse(frame_info.build_id)

    def test_line_with_function(self) -> None:
        line = b"  #08 pc 00001040  /fake/libfake.so (func())"
        frame_info = ndkstack.FrameInfo.from_line(line)
        assert frame_info is not None
        self.assertEqual(b"#08", frame_info.num)
        self.assertEqual(b"00001040", frame_info.pc)
        self.assertEqual(b"/fake/libfake.so (func())", frame_info.tail)
        self.assertEqual(PurePosixPath("/fake/libfake.so"), frame_info.elf_file)
        self.assertFalse(frame_info.offset)
        self.assertFalse(frame_info.container_file)
        self.assertFalse(frame_info.build_id)

    def test_line_with_offset(self) -> None:
        line = b"  #04 pc 00002050  /fake/libfake.so (offset 0x2000)"
        frame_info = ndkstack.FrameInfo.from_line(line)
        assert frame_info is not None
        self.assertEqual(b"#04", frame_info.num)
        self.assertEqual(b"00002050", frame_info.pc)
        self.assertEqual(b"/fake/libfake.so (offset 0x2000)", frame_info.tail)
        self.assertEqual(PurePosixPath("/fake/libfake.so"), frame_info.elf_file)
        self.assertEqual(0x2000, frame_info.offset)
        self.assertFalse(frame_info.container_file)
        self.assertFalse(frame_info.build_id)

    def test_line_with_build_id(self) -> None:
        line = b"  #03 pc 00002050  /fake/libfake.so (BuildId: d1d420a58366bf29f1312ec826f16564)"
        frame_info = ndkstack.FrameInfo.from_line(line)
        assert frame_info is not None
        self.assertEqual(b"#03", frame_info.num)
        self.assertEqual(b"00002050", frame_info.pc)
        self.assertEqual(
            b"/fake/libfake.so (BuildId: d1d420a58366bf29f1312ec826f16564)",
            frame_info.tail,
        )
        self.assertEqual(PurePosixPath("/fake/libfake.so"), frame_info.elf_file)
        self.assertFalse(frame_info.offset)
        self.assertFalse(frame_info.container_file)
        self.assertEqual(b"d1d420a58366bf29f1312ec826f16564", frame_info.build_id)

    def test_line_with_container_file(self) -> None:
        line = b"  #10 pc 00003050  /fake/fake.apk!libc.so"
        frame_info = ndkstack.FrameInfo.from_line(line)
        assert frame_info is not None
        self.assertEqual(b"#10", frame_info.num)
        self.assertEqual(b"00003050", frame_info.pc)
        self.assertEqual(b"/fake/fake.apk!libc.so", frame_info.tail)
        self.assertEqual(PurePosixPath("libc.so"), frame_info.elf_file)
        self.assertFalse(frame_info.offset)
        self.assertEqual(PurePosixPath("/fake/fake.apk"), frame_info.container_file)
        self.assertFalse(frame_info.build_id)

    def test_line_with_container_and_elf_equal(self) -> None:
        line = b"  #12 pc 00004050  /fake/libc.so!lib/libc.so"
        frame_info = ndkstack.FrameInfo.from_line(line)
        assert frame_info is not None
        self.assertEqual(b"#12", frame_info.num)
        self.assertEqual(b"00004050", frame_info.pc)
        self.assertEqual(b"/fake/libc.so!lib/libc.so", frame_info.tail)
        self.assertEqual(PurePosixPath("/fake/libc.so"), frame_info.elf_file)
        self.assertFalse(frame_info.offset)
        self.assertFalse(frame_info.container_file)
        self.assertFalse(frame_info.build_id)

    def test_line_everything(self) -> None:
        line = (
            b"  #07 pc 00823fc  /fake/fake.apk!libc.so (__start_thread+64) "
            b"(offset 0x1000) (BuildId: 6a0c10d19d5bf39a5a78fa514371dab3)"
        )
        frame_info = ndkstack.FrameInfo.from_line(line)
        assert frame_info is not None
        self.assertEqual(b"#07", frame_info.num)
        self.assertEqual(b"00823fc", frame_info.pc)
        self.assertEqual(
            b"/fake/fake.apk!libc.so (__start_thread+64) "
            b"(offset 0x1000) (BuildId: 6a0c10d19d5bf39a5a78fa514371dab3)",
            frame_info.tail,
        )
        self.assertEqual(PurePosixPath("libc.so"), frame_info.elf_file)
        self.assertEqual(0x1000, frame_info.offset)
        self.assertEqual(PurePosixPath("/fake/fake.apk"), frame_info.container_file)
        self.assertEqual(b"6a0c10d19d5bf39a5a78fa514371dab3", frame_info.build_id)

    def test_0x_prefixed_address(self) -> None:
        """Tests that addresses beginning with 0x are parsed correctly."""
        frame_info = ndkstack.FrameInfo.from_line(
            b"  #00  pc 0x000000000006263c  "
            b"/apex/com.android.runtime/lib/bionic/libc.so (abort+172)"
        )
        assert frame_info is not None
        assert frame_info.pc == b"000000000006263c"


@patch.object(ndkstack, "get_build_id")
@patch("os.path.exists")
class VerifyElfFileTests(unittest.TestCase):
    """Tests of verify_elf_file()."""

    def create_frame_info(self) -> ndkstack.FrameInfo:
        line = b"  #03 pc 00002050  /fake/libfake.so"
        frame_info = ndkstack.FrameInfo.from_line(line)
        assert frame_info is not None
        return frame_info

    def test_elf_file_does_not_exist(self, mock_exists: Mock, _: Mock) -> None:
        mock_exists.return_value = False
        frame_info = self.create_frame_info()
        self.assertFalse(
            frame_info.verify_elf_file(None, Path("/fake/libfake.so"), "libfake.so")
        )
        self.assertFalse(
            frame_info.verify_elf_file(
                Path("llvm-readelf"), Path("/fake/libfake.so"), "libfake.so"
            )
        )

    def test_elf_file_build_id_matches(
        self, mock_exists: Mock, mock_get_build_id: Mock
    ) -> None:
        mock_exists.return_value = True
        frame_info = self.create_frame_info()
        frame_info.build_id = b"MOCKED_BUILD_ID"
        self.assertTrue(
            frame_info.verify_elf_file(None, Path("/mocked/libfake.so"), "libfake.so")
        )
        mock_get_build_id.assert_not_called()

        mock_get_build_id.return_value = b"MOCKED_BUILD_ID"
        self.assertTrue(
            frame_info.verify_elf_file(
                Path("llvm-readelf"), Path("/mocked/libfake.so"), "libfake.so"
            )
        )
        mock_get_build_id.assert_called_once_with(
            Path("llvm-readelf"), Path("/mocked/libfake.so")
        )

    def test_elf_file_build_id_does_not_match(
        self, mock_exists: Mock, mock_get_build_id: Mock
    ) -> None:
        mock_exists.return_value = True
        mock_get_build_id.return_value = b"MOCKED_BUILD_ID"
        frame_info = self.create_frame_info()
        frame_info.build_id = b"DIFFERENT_BUILD_ID"
        with patch("sys.stdout", new_callable=StringIO) as mock_stdout:
            self.assertTrue(
                frame_info.verify_elf_file(None, Path("/mocked/libfake.so"), "none.so")
            )
            self.assertFalse(
                frame_info.verify_elf_file(
                    Path("llvm-readelf"), Path("/mocked/libfake.so"), "display.so"
                )
            )
        output = textwrap.dedent(
            """\
            WARNING: Mismatched build id for display.so
            WARNING:   Expected DIFFERENT_BUILD_ID
            WARNING:   Found    MOCKED_BUILD_ID
        """
        )
        self.assertEqual(output, mock_stdout.getvalue())


class GetZipInfoFromOffsetTests(unittest.TestCase):
    """Tests of get_zip_info_from_offset()."""

    def setUp(self) -> None:
        self.mock_zip = mock.MagicMock()
        self.mock_zip.filename = "/fake/zip.apk"
        self.mock_zip.infolist.return_value = []

    def test_file_does_not_exist(self) -> None:
        with self.assertRaises(IOError):
            _ = ndkstack.get_zip_info_from_offset(self.mock_zip, 0x1000)

    @patch("os.stat")
    def test_offset_ge_file_size(self, mock_stat: Mock) -> None:
        mock_stat.return_value.st_size = 0x1000
        self.assertFalse(ndkstack.get_zip_info_from_offset(self.mock_zip, 0x1000))
        self.assertFalse(ndkstack.get_zip_info_from_offset(self.mock_zip, 0x1100))

    @patch("os.stat")
    def test_empty_infolist(self, mock_stat: Mock) -> None:
        mock_stat.return_value.st_size = 0x1000
        self.assertFalse(ndkstack.get_zip_info_from_offset(self.mock_zip, 0x900))

    @patch("os.stat")
    def test_zip_info_single_element(self, mock_stat: Mock) -> None:
        mock_stat.return_value.st_size = 0x2000

        mock_zip_info = mock.MagicMock()
        mock_zip_info.header_offset = 0x100
        self.mock_zip.infolist.return_value = [mock_zip_info]

        self.assertFalse(ndkstack.get_zip_info_from_offset(self.mock_zip, 0x50))

        self.assertFalse(ndkstack.get_zip_info_from_offset(self.mock_zip, 0x2000))

        zip_info = ndkstack.get_zip_info_from_offset(self.mock_zip, 0x200)
        assert zip_info is not None
        self.assertEqual(0x100, zip_info.header_offset)

    @patch("os.stat")
    def test_zip_info_checks(self, mock_stat: Mock) -> None:
        mock_stat.return_value.st_size = 0x2000

        mock_zip_info1 = mock.MagicMock()
        mock_zip_info1.header_offset = 0x100
        mock_zip_info2 = mock.MagicMock()
        mock_zip_info2.header_offset = 0x1000
        self.mock_zip.infolist.return_value = [mock_zip_info1, mock_zip_info2]

        self.assertFalse(ndkstack.get_zip_info_from_offset(self.mock_zip, 0x50))

        zip_info = ndkstack.get_zip_info_from_offset(self.mock_zip, 0x200)
        assert zip_info is not None
        self.assertEqual(0x100, zip_info.header_offset)

        zip_info = ndkstack.get_zip_info_from_offset(self.mock_zip, 0x100)
        assert zip_info is not None
        self.assertEqual(0x100, zip_info.header_offset)

        zip_info = ndkstack.get_zip_info_from_offset(self.mock_zip, 0x1000)
        assert zip_info is not None
        self.assertEqual(0x1000, zip_info.header_offset)


class GetElfFileTests(unittest.TestCase):
    """Tests of FrameInfo.get_elf_file()."""

    def setUp(self) -> None:
        self.mock_zipfile = mock.MagicMock()
        self.mock_zipfile.extract.return_value = "/fake_tmp/libtest.so"
        self.mock_zipfile.__enter__.return_value = self.mock_zipfile

        self.mock_tmp = mock.MagicMock()
        self.mock_tmp.get_directory.return_value = "/fake_tmp"

    # TODO: Refactor so this can specify a real return type.
    # We can't specify anything more accurate than `Any` here because the real return
    # value is a FrameInfo that's had its verify_elf_file method monkey patched with a
    # mock.
    def create_frame_info(self, tail: bytes) -> Any:
        line = b"  #03 pc 00002050  " + tail
        frame_info = ndkstack.FrameInfo.from_line(line)
        assert frame_info is not None
        # mypy can't (and won't) tolerate this.
        # https://github.com/python/mypy/issues/2427
        frame_info.verify_elf_file = mock.Mock()  # type: ignore
        return frame_info

    def test_file_only(self) -> None:
        frame_info = self.create_frame_info(b"/fake/libfake.so")
        frame_info.verify_elf_file.return_value = True
        self.assertEqual(
            Path("/fake_dir/symbols/libfake.so"),
            frame_info.get_elf_file(Path("/fake_dir/symbols"), None, self.mock_tmp),
        )
        frame_info.verify_elf_file.reset_mock()
        frame_info.verify_elf_file.return_value = False
        self.assertFalse(
            frame_info.get_elf_file(Path("/fake_dir/symbols"), None, self.mock_tmp)
        )
        self.assertEqual(b"/fake/libfake.so", frame_info.tail)

    def test_container_set_elf_in_symbol_dir(self) -> None:
        frame_info = self.create_frame_info(b"/fake/fake.apk!libtest.so")
        frame_info.verify_elf_file.return_value = True
        self.assertEqual(
            Path("/fake_dir/symbols/libtest.so"),
            frame_info.get_elf_file(Path("/fake_dir/symbols"), None, self.mock_tmp),
        )
        self.assertEqual(b"/fake/fake.apk!libtest.so", frame_info.tail)

    def test_container_set_elf_not_in_symbol_dir_apk_does_not_exist(self) -> None:
        frame_info = self.create_frame_info(b"/fake/fake.apk!libtest.so")
        frame_info.verify_elf_file.return_value = False
        with self.assertRaises(IOError):
            frame_info.get_elf_file(Path("/fake_dir/symbols"), None, self.mock_tmp)
        self.assertEqual(b"/fake/fake.apk!libtest.so", frame_info.tail)

    @patch.object(ndkstack, "get_zip_info_from_offset")
    @patch("zipfile.ZipFile")
    def test_container_set_elf_not_in_apk(
        self, _: Mock, mock_get_zip_info: Mock
    ) -> None:
        mock_get_zip_info.return_value = None
        frame_info = self.create_frame_info(
            b"/fake/fake.apk!libtest.so (offset 0x2000)"
        )
        frame_info.verify_elf_file.return_value = False
        self.assertFalse(
            frame_info.get_elf_file(Path("/fake_dir/symbols"), None, self.mock_tmp)
        )
        self.assertEqual(b"/fake/fake.apk!libtest.so (offset 0x2000)", frame_info.tail)

    @patch.object(ndkstack, "get_zip_info_from_offset")
    @patch("zipfile.ZipFile")
    def test_container_set_elf_in_apk(
        self, mock_zipclass: Mock, mock_get_zip_info: Mock
    ) -> None:
        mock_zipclass.return_value = self.mock_zipfile
        mock_get_zip_info.return_value.filename = "libtest.so"

        frame_info = self.create_frame_info(
            b"/fake/fake.apk!libtest.so (offset 0x2000)"
        )
        frame_info.verify_elf_file.side_effect = [False, True]
        self.assertEqual(
            Path("/fake_tmp/libtest.so"),
            frame_info.get_elf_file(Path("/fake_dir/symbols"), None, self.mock_tmp),
        )
        self.assertEqual(b"/fake/fake.apk!libtest.so (offset 0x2000)", frame_info.tail)

    @patch.object(ndkstack, "get_zip_info_from_offset")
    @patch("zipfile.ZipFile")
    def test_container_set_elf_in_apk_verify_fails(
        self, mock_zipclass: Mock, mock_get_zip_info: Mock
    ) -> None:
        mock_zipclass.return_value = self.mock_zipfile
        mock_get_zip_info.return_value.filename = "libtest.so"

        frame_info = self.create_frame_info(
            b"/fake/fake.apk!libtest.so (offset 0x2000)"
        )
        frame_info.verify_elf_file.side_effect = [False, False]
        self.assertFalse(
            frame_info.get_elf_file(Path("/fake_dir/symbols"), None, self.mock_tmp)
        )
        self.assertEqual(b"/fake/fake.apk!libtest.so (offset 0x2000)", frame_info.tail)

    def test_in_apk_file_does_not_exist(self) -> None:
        frame_info = self.create_frame_info(b"/fake/fake.apk")
        frame_info.verify_elf_file.return_value = False
        with self.assertRaises(IOError):
            frame_info.get_elf_file(Path("/fake_dir/symbols"), None, self.mock_tmp)
        self.assertEqual(b"/fake/fake.apk", frame_info.tail)

    @patch.object(ndkstack, "get_zip_info_from_offset")
    @patch("zipfile.ZipFile")
    def test_in_apk_elf_not_in_apk(self, _: Mock, mock_get_zip_info: Mock) -> None:
        mock_get_zip_info.return_value = None
        frame_info = self.create_frame_info(b"/fake/fake.apk (offset 0x2000)")
        self.assertFalse(
            frame_info.get_elf_file(Path("/fake_dir/symbols"), None, self.mock_tmp)
        )
        self.assertEqual(b"/fake/fake.apk (offset 0x2000)", frame_info.tail)

    @patch.object(ndkstack, "get_zip_info_from_offset")
    @patch("zipfile.ZipFile")
    def test_in_apk_elf_in_symbol_dir(
        self, mock_zipclass: Mock, mock_get_zip_info: Mock
    ) -> None:
        mock_zipclass.return_value = self.mock_zipfile
        mock_get_zip_info.return_value.filename = "libtest.so"

        frame_info = self.create_frame_info(b"/fake/fake.apk (offset 0x2000)")
        frame_info.verify_elf_file.return_value = True
        self.assertEqual(
            Path("/fake_dir/symbols/libtest.so"),
            frame_info.get_elf_file(Path("/fake_dir/symbols"), None, self.mock_tmp),
        )
        self.assertEqual(b"/fake/fake.apk!libtest.so (offset 0x2000)", frame_info.tail)

    @patch.object(ndkstack, "get_zip_info_from_offset")
    @patch("zipfile.ZipFile")
    def test_in_apk_elf_in_apk(
        self, mock_zipclass: Mock, mock_get_zip_info: Mock
    ) -> None:
        mock_zipclass.return_value = self.mock_zipfile
        mock_get_zip_info.return_value.filename = "libtest.so"

        frame_info = self.create_frame_info(b"/fake/fake.apk (offset 0x2000)")
        frame_info.verify_elf_file.side_effect = [False, True]
        self.assertEqual(
            Path("/fake_tmp/libtest.so"),
            frame_info.get_elf_file(Path("/fake_dir/symbols"), None, self.mock_tmp),
        )
        self.assertEqual(b"/fake/fake.apk!libtest.so (offset 0x2000)", frame_info.tail)

    @patch.object(ndkstack, "get_zip_info_from_offset")
    @patch("zipfile.ZipFile")
    def test_in_apk_elf_in_apk_verify_fails(
        self, mock_zipclass: Mock, mock_get_zip_info: Mock
    ) -> None:
        mock_zipclass.return_value = self.mock_zipfile
        mock_get_zip_info.return_value.filename = "libtest.so"

        frame_info = self.create_frame_info(b"/fake/fake.apk (offset 0x2000)")
        frame_info.verify_elf_file.side_effect = [False, False]
        self.assertFalse(
            frame_info.get_elf_file(Path("/fake_dir/symbols"), None, self.mock_tmp)
        )
        self.assertEqual(b"/fake/fake.apk!libtest.so (offset 0x2000)", frame_info.tail)


if __name__ == "__main__":
    unittest.main()
