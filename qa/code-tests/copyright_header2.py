#!/usr/bin/env python3
# Copyright (c) 2017 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import re
import sys
import os
import itertools
import argparse

from framework.file_filter import FileFilter
from framework.file_info import FileInfo
from framework.file_content_cmd import FileContentCmd
from framework.args import add_jobs_arg
from framework.args import add_json_arg
from framework.git import add_git_tracked_targets_arg
from framework.style import StyleDiff, StyleScore

###############################################################################
# define which files the rules apply to
###############################################################################

# this script is only applied to files in 'git ls-files' of these extensions:
SOURCE_FILES = ['*.h', '*.cpp', '*.cc', '*.c', '*.py', '*.sh', '*.am', '*.m4',
                '*.include']

REPO_INFO = {
    'subtrees': [
        'src/secp256k1/*',
        'src/leveldb/*',
        'src/univalue/*',
        'src/crypto/ctaes/*',
    ],
    'no_copyright_header': [
        '*__init__.py',
        'doc/man/Makefile.am',
        'build-aux/m4/ax_boost_base.m4',
        'build-aux/m4/ax_boost_chrono.m4',
        'build-aux/m4/ax_boost_filesystem.m4',
        'build-aux/m4/ax_boost_program_options.m4',
        'build-aux/m4/ax_boost_system.m4',
        'build-aux/m4/ax_boost_thread.m4',
        'build-aux/m4/ax_boost_unit_test_framework.m4',
        'build-aux/m4/ax_check_compile_flag.m4',
        'build-aux/m4/ax_check_link_flag.m4',
        'build-aux/m4/ax_check_preproc_flag.m4',
        'build-aux/m4/ax_cxx_compile_stdcxx.m4',
        'build-aux/m4/ax_gcc_func_attribute.m4',
        'build-aux/m4/ax_pthread.m4',
        'build-aux/m4/l_atomic.m4',
        'src/qt/bitcoinstrings.cpp',
        'src/chainparamsseeds.h',
        'src/tinyformat.h',
        'qa/rpc-tests/test_framework/bignum.py',
        'contrib/devtools/clang-format-diff.py',
        'qa/rpc-tests/test_framework/authproxy.py',
        'qa/rpc-tests/test_framework/key.py',
    ],
    'other_copyright_occurrences': [
        'qa/code-tests/copyright_header.py',
        'contrib/devtools/gen-manpages.sh',
        'share/qt/extract_strings_qt.py',
        'src/Makefile.qt.include',
        'src/clientversion.h',
        'src/init.cpp',
        'src/qt/bitcoinstrings.cpp',
        'src/qt/splashscreen.cpp',
        'src/util.cpp',
        'src/util.h',
        'src/tinyformat.h',
        'contrib/devtools/clang-format-diff.py',
        'qa/rpc-tests/test_framework/authproxy.py',
        'qa/rpc-tests/test_framework/key.py',
        'contrib/devtools/git-subtree-check.sh',
        'build-aux/m4/l_atomic.m4',
        'build-aux/m4/ax_boost_base.m4',
        'build-aux/m4/ax_boost_chrono.m4',
        'build-aux/m4/ax_boost_filesystem.m4',
        'build-aux/m4/ax_boost_program_options.m4',
        'build-aux/m4/ax_boost_system.m4',
        'build-aux/m4/ax_boost_thread.m4',
        'build-aux/m4/ax_boost_unit_test_framework.m4',
        'build-aux/m4/ax_check_compile_flag.m4',
        'build-aux/m4/ax_check_link_flag.m4',
        'build-aux/m4/ax_check_preproc_flag.m4',
        'build-aux/m4/ax_cxx_compile_stdcxx.m4',
        'build-aux/m4/ax_gcc_func_attribute.m4',
        'build-aux/m4/ax_pthread.m4',
    ],
}

###############################################################################
# regexes
###############################################################################

YEAR = "20[0-9][0-9]"
YEAR_RANGE = '(?P<start_year>%s)(-(?P<end_year>%s))?' % (YEAR, YEAR)

YEAR_RANGE_COMPILED = re.compile(YEAR_RANGE)

###############################################################################
# header regex and ignore list for the base bitcoin core repository
###############################################################################

HOLDERS = [
    "Satoshi Nakamoto",
    "The Bitcoin Core developers",
    "Pieter Wuille",
    "Wladimir J\\. van der Laan",
    "Jeff Garzik",
    "BitPay Inc\\.",
    "MarcoFalke",
    "ArtForz -- public domain half-a-node",
    "Jeremy Rubin",
]
ANY_HOLDER = '|'.join([h for h in HOLDERS])
COPYRIGHT_LINE = (
    "(#|//|dnl) Copyright \\(c\\) %s (%s)" % (YEAR_RANGE, ANY_HOLDER))
LAST_TWO_LINES = ("(#|//|dnl) Distributed under the MIT software license, see "
                  "the accompanying\n(#|//|dnl) file COPYING or "
                  "http://www\\.opensource\\.org/licenses/mit-license\\.php\\."
                  "\n")

HEADER = "(%s\n)+%s" % (COPYRIGHT_LINE, LAST_TWO_LINES)

HEADER_COMPILED = re.compile(HEADER)

OTHER_COPYRIGHT = "(Copyright|COPYRIGHT|copyright)"
OTHER_COPYRIGHT_COMPILED = re.compile(OTHER_COPYRIGHT)

###############################################################################
# get file info
###############################################################################


ISSUE_1 = {
    'description': "A valid header was expected, but the file does not match "
                   "the regex.",
    'resolution': """
A correct MIT License header copyrighted by 'The Bitcoin Core developers' in
the present year can be inserted into a file by running:

    $ ./copyright_header.py insert <filename>

If there was a preexisting invalid header in the file, that will need to be
manually deleted. If there is a new copyright holder for the MIT License, the
holder will need to be added to the HOLDERS list to include it in the regex
check.
"""
}

ISSUE_2 = {
    'description': "A valid header was found in the file, but it wasn't "
                   "expected.",
    'resolution': """
The header was not expected due to a setting in copyright_header.py. If a valid
copyright header has been added to the file, the filename can be removed from
the NO_HEADER_EXPECTED listing.
"""
}

ISSUE_3 = {
    'description': "Another 'copyright' occurrence was found, but it wasn't "
                   "expected.",
    'resolution': """
This file's body has a regular expression match for the (case-sensitive) words
"Copyright", "COPYRIGHT" or 'copyright". If this was an appropriate addition,
copyright_header.py can be edited to add the file to the
OTHER_COPYRIGHT_EXPECTED listing.
"""
}

ISSUE_4 = {
    'description': "Another 'copyright' occurrence was expected, but wasn't "
                   "found.",
    'resolution': """
A use of the (case-sensitive) words "Copyright", "COPYRIGHT", or 'copyright'
outside of the regular copyright header was expected due to a setting in
copyright_header.py but it was not found. If this text was appropriately
removed from the file, copyright_header.py can be edited to remove the file
from the OTHER_COPYRIGHT_EXPECTED listing.
"""
}

NO_ISSUE = {
    'description': "Everything is excellent",
    'resolution': "(none)"
}

ISSUES = [ISSUE_1, ISSUE_2, ISSUE_3, ISSUE_4, NO_ISSUE]


SCRIPT_HEADER = ("# Copyright (c) %s The Bitcoin Core developers\n"
                 "# Distributed under the MIT software license, see the "
                 "accompanying\n# file COPYING or http://www.opensource.org/"
                 "licenses/mit-license.php.\n")

CPP_HEADER = ("// Copyright (c) %s The Bitcoin Core developers\n// "
              "Distributed under the MIT software license, see the "
              "accompanying\n// file COPYING or http://www.opensource.org/"
              "licenses/mit-license.php.\n")

###############################################################################
# file info
###############################################################################

class CopyrightHeaderFileInfo(FileInfo):
    """
    Obtains and represents the information regarding a single file.
    """
    def __init__(self, repository, file_path, copyright_expected,
                 other_copyright_expected):
        super().__init__(repository, file_path)
        self['hdr_expected'] = copyright_expected
        self['other_copyright_expected'] = other_copyright_expected

    def _starts_with_shebang(self):
        if len(self['content']) < 2:
            return False
        return self['content'][:2] == '#!'

    def _header_match_in_correct_place(self, header_match):
        start = header_match.start(0)
        shebang = self._starts_with_shebang()
        if start == 0:
            return not shebang
        return shebang and (self['content'][:start].count('\n') == 1)

    def _has_header(self):
        header_match = HEADER_COMPILED.search(self['content'])
        if not header_match:
            return False
        return self._header_match_in_correct_place(header_match)

    def _has_copyright_in_region(self, content_region):
        return OTHER_COPYRIGHT_COMPILED.search(content_region) is not None

    def _has_other_copyright(self):
        # look for the OTHER_COPYRIGHT regex outside the normal header regex
        # match
        header_match = HEADER_COMPILED.search(self['content'])
        region = (self['content'][header_match.end():] if header_match else
                  self['content'])
        return self._has_copyright_in_region(region)

    def _evaluate(self):
        if not self['has_header'] and self['hdr_expected']:
            return ISSUE_1
        if self['has_header'] and not self['hdr_expected']:
            return ISSUE_2
        if self['has_other'] and not self['other_copyright_expected']:
            return ISSUE_3
        if not self['has_other'] and self['other_copyright_expected']:
            return ISSUE_4
        return NO_ISSUE

    def compute(self):
        self['has_header'] = self._has_header()
        self['has_other'] = self._has_other_copyright()
        self['evaluation'] = self._evaluate()
        self['pass'] = self['evaluation'] is NO_ISSUE


###############################################################################
# cmd base class
###############################################################################

class CopyrightHeaderCmd(FileContentCmd):
    """
    Common base class for the commands in this script.
    """
    def __init__(self, repository, jobs, target_fnmatches, json):
        super().__init__(repository, jobs, SOURCE_FILES, REPO_INFO['subtrees'],
                         target_fnmatches, json)
        self.no_copyright_filter = FileFilter()
        self.no_copyright_filter.append_include(
            REPO_INFO['no_copyright_header'], base_path=str(repository))
        self.other_copyright_filter = FileFilter()
        self.other_copyright_filter.append_include(
            REPO_INFO['other_copyright_occurrences'],
            base_path=str(repository))

    def _copyright_expected(self, file_path):
        return not self.no_copyright_filter.evaluate(file_path)

    def _other_copyright_expected(self, file_path):
        return self.other_copyright_filter.evaluate(file_path)

    def _file_info_list(self):
        return [CopyrightHeaderFileInfo(self.repository, f,
                                        self._copyright_expected(f),
                                        self._other_copyright_expected(f))
                for f in self.files_targeted]


###############################################################################
# report cmd
###############################################################################

class ReportCmd(CopyrightHeaderCmd):
    """
    'report' subcommand class.
    """
    def _analysis(self):
        a = super()._analysis()
        a['hdr_expected'] = sum(1 for f in self.file_infos if
                                f['hdr_expected'])
        a['no_hdr_expected'] = sum(1 for f in self.file_infos if not
                                   f['hdr_expected'])
        a['other_copyright_expected'] = sum(1 for f in self.file_infos if
                                            f['other_copyright_expected'])
        a['no_other_copyright_expected'] = sum(1 for f in self.file_infos if not
                                               f['other_copyright_expected'])
        a['passed'] = sum(1 for f in self.file_infos if f['pass'])
        a['failed'] = sum(1 for f in self.file_infos if not f['pass'])
        a['issues'] = {}
        for issue in ISSUES:
            a['issues'][issue['description']] = sum(
                1 for f in self.file_infos if
                f['evaluation']['description'] == issue['description'])
        return a

    def _human_print(self):
        super()._human_print()
        r = self.report
        a = self.results
        r.add("%-70s %6d\n" % ("Files expected to have header:",
                               a['hdr_expected']))
        r.add("%-70s %6d\n" % ("Files not expected to have header:",
                               a['no_hdr_expected']))
        r.add("%-70s %6d\n" %
              ("Files expected to have 'copyright' occurrence outside header:",
               a['other_copyright_expected']))
        r.add("%-70s %6d\n" %
              ("Files not expected to have 'copyright' occurrence outside "
              "header:", a['no_other_copyright_expected']))
        r.add("%-70s %6d\n" % ("Files passed:", a['passed']))
        r.add("%-70s %6d\n" % ("Files failed:", a['failed']))
        r.separator()
        for key, value in sorted(a['issues'].items()):
            r.add("%-70s %6d\n" % ('"' + key + '":', value))
        r.separator()
        r.flush()


def add_report_cmd(subparsers):
    def exec_report_cmd(options):
        ReportCmd(options.repository, options.jobs,
                  options.target_fnmatches, options.json).exec()

    report_help = ("Produces a report of copyright header notices and "
                   "identifies")
    parser = subparsers.add_parser('report', help=report_help)
    parser.set_defaults(func=exec_report_cmd)
    add_jobs_arg(parser)
    add_json_arg(parser)
    add_git_tracked_targets_arg(parser)


###############################################################################
# check cmd
###############################################################################

class CheckCmd(CopyrightHeaderCmd):
    """
    'check' subcommand class.
    """

    def _analysis(self):
        a = super()._analysis()
        a['issues'] = [{'file_path':  f['file_path'],
                        'evaluation': f['evaluation']} for f in
                       self.file_infos if not f['pass']]
        return a

    def _human_print(self):
        super()._human_print()
        r = self.report
        a = self.results
        for issue in a['issues']:
            r.add("An issue was found with ")
            r.add_red("%s" % issue['file_path'])
            r.add('\n\n%s\n\n' % issue['evaluation']['description'])
            r.add('Info for resolution:\n')
            r.add(issue['evaluation']['resolution'])
            r.separator()
        if len(a['issues']) == 0:
            r.add_green("No copyright header issues found!\n")
        r.flush()

    def _json_print(self):
        a = self.results
        for issue in a['issues']:
            issue['evaluation'].pop('resolution', None)
        super()._json_print()

    def _shell_exit(self):
        return (0 if len(self.results['issues']) == 0 else
                "*** copyright header issue found")


def add_check_cmd(subparsers):
    def exec_check_cmd(options):
        CheckCmd(options.repository, options.jobs,
                 options.target_fnmatches, options.json).exec()

    check_help = ("")
    parser = subparsers.add_parser('check', help=check_help)
    parser.set_defaults(func=exec_check_cmd)
    add_jobs_arg(parser)
    add_json_arg(parser)
    add_git_tracked_targets_arg(parser)


###############################################################################
# update cmd
###############################################################################

class UpdateCmd(CopyrightHeaderCmd):
    """
    'update' subcommand class.
    """
    def __init__(self, repository, target_fnmatches):
        super().__init__(repository, 1, target_fnmatches, False)

    def _compute_file_infos(self):
        super()._compute_file_infos()
        for file_info in self.file_infos:
           file_info.set_write_content(file_info['content'])

    def _write_files(self):
        self.file_infos.write_all()


def add_update_cmd(subparsers):
    def exec_update_cmd(options):
        UpdateCmd(options.repository, options.target_fnmatches).exec_write()

    update_help = ("")
    parser = subparsers.add_parser('update', help=update_help)
    parser.set_defaults(func=exec_update_cmd)
    add_git_tracked_targets_arg(parser)

###############################################################################
# UI
###############################################################################


if __name__ == "__main__":
    description = ("utilities for managing copyright headers of 'The Bitcoin "
                   "Core developers' in repository source files")
    parser = argparse.ArgumentParser(description=description)
    subparsers = parser.add_subparsers()
    add_report_cmd(subparsers)
    add_check_cmd(subparsers)
    add_update_cmd(subparsers)
    options = parser.parse_args()
    if not hasattr(options, "func"):
        parser.print_help()
        sys.exit("*** missing argument")
    options.func(options)
