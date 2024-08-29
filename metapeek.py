""" Metadata Anomaly Detection service.

This service is intended to look for anomalies based on metadata only.
It does not require fetching the actual sample.
"""

import os
import posixpath
import re

from assemblyline.common.str_utils import remove_bidir_unicode_controls, wrap_bidir_unicode_string
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import Heuristic, Result, ResultSection
from bidi.algorithm import get_display

# This list is incomplete. Feel free to add entries. Must be uppercase
G_LAUNCHABLE_EXTENSIONS = [
    "AS",  # Adobe ActionScript
    "BAT",  # DOS/Windows batch file
    "CMD",  # Windows Command
    "COM",  # DOS Command
    "DLL",  # Windows library
    "EXE",  # DOS/Windows executable
    "INF",  # Windows autorun
    "JS",  # JavaScript
    "LNK",  # Windows shortcut
    "SCR",  # Windows screensaver
    "URL",  # Windows URL Shortcut
]

# We do not want to look for double extension on LNK files
G_LAUNCHABLE_EXTENSIONS_DOUBLE_EXT = G_LAUNCHABLE_EXTENSIONS[:]
G_LAUNCHABLE_EXTENSIONS_DOUBLE_EXT.remove("LNK")
G_LAUNCHABLE_EXTENSIONS_DOUBLE_EXT.remove("URL")

# This list is incomplete. Feel free to add entries. Must be uppercase
G_BAIT_EXTENSIONS = [
    "BMP",  # Bitmap image
    "DOC",  # MS Word document
    "DOCX",  # MS Word document
    "DOT",  # MS Word template
    "EXCEL",  # MS spreadsheet
    "JPG",  # JPEG image
    "JPEG",  # JPEG image
    "PDF",  # Acrobat PDF
    "PNG",  # Image
    "PPT",  # MS PowerPoint
    "PPTX",  # MS PowerPoint
    "TEXT",  # Plain old text doc
    "TXT",  # Plain old text doc
    "WORD",  # MS Word document
    "XLS",  # MS spreadsheet
    "XLSX",  # MS spreadsheet
    "ZIP",  # Compressed file
]

# Reversed extensions are used in unicode extension hiding attacks
G_BAIT_EXTENSIONS += [file_ext[::-1] for file_ext in G_BAIT_EXTENSIONS]

PHISHING_CHAR = [
    # b"\xe2\x84\xa2".decode(), # ™
    b"\xe2\x8f\xad".decode(),  # ⏭
    b"\xe2\x8f\xae".decode(),  # ⏮
    # b"\xe2\x94\x80".decode(), # ─
    b"\xe2\x96\xb6".decode(),  # ▶️
    b"\xe2\x98\x8e".decode(),  # ☎
    b"\xe2\x99\xab".decode(),  # ♫
    b"\xf0\x9f\x8e\xb6".decode(),  # 🎶
    b"\xf0\x9f\x93\x83".decode(),  # 📃
    b"\xf0\x9f\x93\x84".decode(),  # 📄
    b"\xf0\x9f\x93\x8c".decode(),  # 📌
    b"\xf0\x9f\x93\x9e".decode(),  # 📞
    b"\xf0\x9f\x93\xa0".decode(),  # 📠
    b"\xf0\x9f\x93\xa7".decode(),  # 📧
    b"\xf0\x9f\x93\xa8".decode(),  # 📨
    b"\xf0\x9f\x93\xa9".decode(),  # 📩
    b"\xf0\x9f\x93\xaa".decode(),  # 📪
    b"\xf0\x9f\x93\xab".decode(),  # 📫
    b"\xf0\x9f\x93\xac".decode(),  # 📬
    b"\xf0\x9f\x93\xad".decode(),  # 📭
    b"\xf0\x9f\x94\x87".decode(),  # 🔇
    b"\xf0\x9f\x94\x88".decode(),  # 🔈
    b"\xf0\x9f\x94\x89".decode(),  # 🔉
    b"\xf0\x9f\x94\x8a".decode(),  # 🔊
    b"\xf0\x9f\x94\x8f".decode(),  # 🔏
    b"\xf0\x9f\x94\x90".decode(),  # 🔐
    b"\xf0\x9f\x94\x91".decode(),  # 🔑
    b"\xf0\x9f\x94\x92".decode(),  # 🔒
    b"\xf0\x9f\x94\x93".decode(),  # 🔓
    b"\xf0\x9f\x94\x94".decode(),  # 🔔
    b"\xf0\x9f\x94\x95".decode(),  # 🔕
    b"\xf0\x9f\x94\x96".decode(),  # 🔖
    b"\xf0\x9f\x95\xa8".decode(),  # 🕨
    b"\xf0\x9f\x95\xa9".decode(),  # 🕩
    b"\xf0\x9f\x95\xaa".decode(),  # 🕪
    b"\xf0\x9f\x95\xab".decode(),  # 🕫
    b"\xf0\x9f\x95\xac".decode(),  # 🕬
    b"\xf0\x9f\x95\xad".decode(),  # 🕭
    b"\xf0\x9f\x95\xbb".decode(),  # 🕻
    b"\xf0\x9f\x95\xbc".decode(),  # 🕼
    b"\xf0\x9f\x95\xbd".decode(),  # 🕽
    b"\xf0\x9f\x95\xbe".decode(),  # 🕾
    b"\xf0\x9f\x95\xbf".decode(),  # 🕿
    b"\xf0\x9f\x96\x80".decode(),  # 🖀
    b"\xf0\x9f\x96\x81".decode(),  # 🖁
    b"\xf0\x9f\x96\x82".decode(),  # 🖂
    b"\xf0\x9f\x96\x83".decode(),  # 🖃
    b"\xf0\x9f\x96\x84".decode(),  # 🖄
    b"\xf0\x9f\x96\x85".decode(),  # 🖅
    b"\xf0\x9f\x96\x86".decode(),  # 🖆
    b"\xf0\x9f\x96\xa8".decode(),  # 🖨
    b"\xf0\x9f\x9b\x8d".decode(),  # 🛍️
]

RTL_CTRLS = ["\u202E", "\u202B", "\u200F"]
LTR_CTRLS = ["\u202D", "\u202A", "\u200E"]
POP_CTRLS = ["\u202C"]

BIDIR_CTRLS = RTL_CTRLS + LTR_CTRLS + POP_CTRLS


class MetaPeek(ServiceBase):
    def __init__(self, config=None):
        super(MetaPeek, self).__init__(config)

    def execute(self, request: ServiceRequest):
        request.result = self.check_file_name_anomalies(request)
        return

    @staticmethod
    def fna_check_double_extension(filename):
        """
        Double extension
        A very simple check. If we have two short file extensions
        back-to-back, with the last one launchable
        """

        file_ext_min = 2  # shortest extension we care about, excluding the '.'
        file_ext_max = 4  # longest extension we care about, excluding the '.'

        _, file_ext_1 = os.path.splitext(filename)
        file_ext_1 = remove_bidir_unicode_controls(file_ext_1.strip())
        # Ignore files with a '.' but nothing after
        if (
            file_ext_min < len(file_ext_1) <= file_ext_max + 1
            and file_ext_1[1:].upper() in G_LAUNCHABLE_EXTENSIONS_DOUBLE_EXT
        ):
            _, file_ext_2 = os.path.splitext(filename[: len(filename) - len(file_ext_1)])
            file_ext_2 = remove_bidir_unicode_controls(file_ext_2.strip())
            if file_ext_min < len(file_ext_2) <= file_ext_max + 1 and file_ext_2[1:].upper() in G_BAIT_EXTENSIONS:
                return True, file_ext_1

        return False, file_ext_1

    @staticmethod
    def fna_check_empty_filename(filename, f_ext):
        """
        Check for file names with extension only (".exe", ...etc).
        This could be used with a path to look legit (e.g. "/Explorer/.exe")
        This also applies to file names that are all whitespaces + extension
        """

        if len(f_ext) > 0:
            filename_no_ext = filename[: len(filename) - len(f_ext)]
            # Also catch file names that are all spaces
            if len(filename_no_ext) == 0 or filename_no_ext.isspace():
                if f_ext[1:].upper() in G_LAUNCHABLE_EXTENSIONS:
                    return True

        return False

    @staticmethod
    def fna_check_filename_ws(filename, f_ext):
        """
        File names with long sequences of whitespaces
        (for now, only spaces and tabs are counted)
        Also detect fillers such as: "!@#$%^&()_+*"
        """

        ws_count = len(re.findall("[- \t!@#$^&()=+*%]", filename))
        # More than half of file name is whitespaces?
        # At least 10 whitespaces altogether.
        if (ws_count << 1) > len(filename) and ws_count >= 10:
            if f_ext[1:].upper() in G_LAUNCHABLE_EXTENSIONS:
                return True

        return False

    @staticmethod
    def fna_check_unicode_bidir_ctrls(filename, f_ext):
        """
        Detect Unicode RTLO
        This attack vector could use any combination of unicode values:
        0x202E (RTL Override), 0x202B (RTL Embedding), # 0x202D (LTR
        Override), or 0x202A (LTR Embedding). It is used to hide the
        executible extension of a file. Although not used before in
        malware, 0x200E (LTR Mark) and 0x200F (RTL Mark) are also checked
        as they can potentially be used.
        Samples can be found using:
        0x202B: https://www.virustotal.com/gui/search/name%253A%25E2%2580%25AB*/files
        0x202E: https://www.virustotal.com/gui/search/name%253A%25E2%2580%25AE*/files
        """

        if not isinstance(filename, str):
            return False

        if not any(c in filename for c in BIDIR_CTRLS):
            return False

        # get_display does not handle Explicit Directional Isolates, so we'll replace them.
        filename = (
            filename.replace("\u2066", "\u202A")  # Replace LRI with LRE
            .replace("\u2067", "\u202B")  # Replace RLI with RLE
            .replace("\u2068", "")  # Replace FSI with nothing?
            .replace("\u2069", "\u202C")  # Replace PDI with PDF
        )

        _, f_ext_display = os.path.splitext(get_display(filename))
        f_ext_display = remove_bidir_unicode_controls(f_ext_display)

        return f_ext_display and 3 <= len(f_ext_display) <= 5 and f_ext != f_ext_display

    def check_file_name_anomalies(self, request: ServiceRequest):
        """Filename anomalies detection"""
        filename = posixpath.basename(request.file_name)

        is_double_ext, f_ext = self.fna_check_double_extension(filename)
        is_empty_filename = self.fna_check_empty_filename(filename, f_ext)
        too_many_whitespaces = self.fna_check_filename_ws(filename, f_ext)
        has_unicode_ext_hiding_ctrls = self.fna_check_unicode_bidir_ctrls(filename, f_ext)
        phishing_char_html = request.file_type == "code/html" and any(c in filename for c in PHISHING_CHAR)

        file_res = Result()

        if (
            too_many_whitespaces
            or is_double_ext
            or has_unicode_ext_hiding_ctrls
            or is_empty_filename
            or phishing_char_html
        ):
            res = ResultSection(title_text="File Name Anomalies", parent=file_res)

            # Tag filename as it might be of interest
            res.add_tag("file.name.extracted", filename)

            # Remove Unicode controls, if any, for reporting
            fn_no_controls = remove_bidir_unicode_controls(filename)

            # Also add a line with "actual" file name
            res.add_line(f"Actual file name: {wrap_bidir_unicode_string(fn_no_controls)}")

            if too_many_whitespaces:
                sec = ResultSection("Too many whitespaces", parent=res, heuristic=Heuristic(1))
                sec.add_tag("file.name.anomaly", "TOO_MANY_WHITESPACES")
                sec.add_tag("file.behavior", "File name has too many whitespaces")

            if is_double_ext:
                sec = ResultSection("Double file extension", parent=res, heuristic=Heuristic(2))
                sec.add_tag("file.name.anomaly", "DOUBLE_FILE_EXTENSION")
                sec.add_tag("file.behavior", "Double file extension")

            if has_unicode_ext_hiding_ctrls:
                sec = ResultSection("Hidden launchable file extension", parent=res, heuristic=Heuristic(3))
                sec.add_tag("file.name.anomaly", "UNICODE_EXTENSION_HIDING")
                sec.add_tag("file.behavior", "Real file extension hidden using unicode trickery")

            if is_empty_filename:
                sec = ResultSection("Empty Filename", parent=res, heuristic=Heuristic(4))
                sec.add_tag("file.name.anomaly", "FILENAME_EMPTY_OR_ALL_SPACES")
                sec.add_tag("file.behavior", "File name is empty or all whitespaces")

            if phishing_char_html:
                sec = ResultSection("Phishing Character in HTML filename", parent=res, heuristic=Heuristic(5))
                sec.add_tag("file.name.anomaly", "PHISHING_CHAR_HTML")

        return file_res
