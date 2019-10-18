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
from assemblyline_v4_service.common.result import Result, ResultSection, Heuristic

# This list is incomplete. Feel free to add entries. Must be uppercase
G_LAUNCHABLE_EXTENSIONS = [
    'AS',   # Adobe ActionScript
    'BAT',  # DOS/Windows batch file
    'CMD',  # Windows Command
    'COM',  # DOS Command
    'EXE',  # DOS/Windows executable
    'DLL',  # Windows library
    'INF',  # Windows autorun
    'JS',   # JavaScript
    'LNK',  # Windows shortcut
    'SCR',  # Windows screensaver
]

# This list is incomplete. Feel free to add entries. Must be uppercase
G_BAIT_EXTENSIONS = [
    'BMP',   # Bitmap image
    'DOC',   # MS Word document
    'DOCX',  # MS Word document
    'DOT',   # MS Word template
    'JPG',   # JPEG image
    'JPEG',  # JPEG image
    'PDF',   # Acrobat PDF
    'PNG',   # Image
    'PPT',   # MS PowerPoint
    'TXT',   # Plain old text doc
    'XLS',   # MS spreadsheet
    'ZIP',   # Compressed file
]

# Reversed extensions are used in unicode extension hiding attacks
G_BAIT_EXTENSIONS += [file_ext[::-1] for file_ext in G_BAIT_EXTENSIONS]


class MetaPeek(ServiceBase):
    def __init__(self, config=None):
        super(MetaPeek, self).__init__(config)

    def execute(self, request: ServiceRequest):
        filename = posixpath.basename(request.file_name)
        request.result = self.check_file_name_anomalies(filename)
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
        if file_ext_min < len(file_ext_1) <= file_ext_max + 1:
            _, file_ext_2 = os.path.splitext(
                filename[:len(filename) - len(file_ext_1)])
            file_ext_2 = remove_bidir_unicode_controls(file_ext_2.strip())
            if file_ext_min < len(file_ext_2) <= file_ext_max + 1:
                if file_ext_1[1:].upper() in G_LAUNCHABLE_EXTENSIONS and file_ext_2[1:].upper() in G_BAIT_EXTENSIONS:
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
            filename_no_ext = filename[:len(filename) - len(f_ext)]
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

        ws_count = len(re.findall('[- \t!@#$^&()=+*%]', filename))
        # More than half of file name is whitespaces? 
        # At least 10 whitespaces altogether.
        if (ws_count << 1) > len(filename) and ws_count >= 10:
            if f_ext[1:].upper() in G_LAUNCHABLE_EXTENSIONS:
                return True

        return False

    @staticmethod
    def fna_check_unicode_bidir_ctrls(filename, f_ext):
        """ Detect Unicode RTLO
            This attack vector could use any combination of unicode values: 
            0x202E (RTL Override), 0x202B (RTL Embedding), # 0x202D (LTR 
            Override), or 0x202A (LTR Embedding). It is used to hide the 
            executible extension of a file. Although not used before in 
            malware, 0x200E (LTR Mark) and 0x200F (RTL Mark) are also checked 
            as they can potentially be used.
        """

        if isinstance(filename, str):
            re_obj = re.search(r'[\u202E\u202B\u202D\u202A\u200E\u200F]',
                               filename)
            if re_obj is not None and len(re_obj.group()) > 0:
                if f_ext[1:].upper() in G_LAUNCHABLE_EXTENSIONS:
                    return True

        return False

    def check_file_name_anomalies(self, filename):
        """ Filename anomalies detection"""

        is_double_ext, f_ext = self.fna_check_double_extension(filename)
        is_empty_filename = self.fna_check_empty_filename(filename, f_ext)
        too_many_whitespaces = self.fna_check_filename_ws(filename, f_ext)
        has_unicode_ext_hiding_ctrls = self.fna_check_unicode_bidir_ctrls(filename, f_ext)

        file_res = Result()

        if too_many_whitespaces or is_double_ext or has_unicode_ext_hiding_ctrls or is_empty_filename:
            res = ResultSection(title_text="File Name Anomalies", parent=file_res)

            # Tag filename as it might be of interest
            res.add_tag('file.name.extracted', filename)

            # Remove Unicode controls, if any, for reporting
            fn_no_controls = ''.join(c for c in filename
                                     if c not in ['\u202E', '\u202B', '\u202D',
                                                  '\u202A', '\u200E', '\u200F'])

            # Also add a line with "actual" file name
            res.add_line(f"Actual file name: {wrap_bidir_unicode_string(fn_no_controls)}")

            if too_many_whitespaces:
                sec = ResultSection("Too many whitespaces", parent=res, heuristic=Heuristic(1))
                sec.add_tag('file.name.anomaly', 'TOO_MANY_WHITESPACES')
                sec.add_tag('file.behavior', "File name has too many whitespaces")

            if is_double_ext:
                sec = ResultSection("Double file extension", parent=res, heuristic=Heuristic(2))
                sec.add_tag('file.name.anomaly', 'DOUBLE_FILE_EXTENSION')
                sec.add_tag('file.behavior', "Double file extension")

            if has_unicode_ext_hiding_ctrls:
                sec = ResultSection("Hidden launchable file extension", parent=res, heuristic=Heuristic(3))
                sec.add_tag('file.name.anomaly', 'UNICODE_EXTENSION_HIDING')
                sec.add_tag('file.behavior', "Real file extension hidden using unicode trickery")

            if is_empty_filename:
                sec = ResultSection("Empty Filename", parent=res, heuristic=Heuristic(4))
                sec.add_tag('file.name.anomaly', 'FILENAME_EMPTY_OR_ALL_SPACES')
                sec.add_tag('file.behavior', "File name is empty or all whitespaces")

        return file_res
