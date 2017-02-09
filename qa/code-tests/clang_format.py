#!/usr/bin/env python3
# Copyright (c) 2017 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import sys
import os
import time
import argparse
import difflib
import hashlib

from framework.report import Report
from framework.clang import add_clang_format_args, clang_format_from_options
from framework.file_info import FileInfo
from framework.file_content_cmd import FileContentCmd
from framework.args import add_jobs_arg
from framework.args import add_force_arg
from framework.args import add_json_arg
from framework.git import add_git_tracked_targets_arg

###############################################################################
# settings for the set of files that this applies to
###############################################################################

SOURCE_FILES = ['*.cpp', '*.h']

REPO_INFO = {
    'subtrees':                 ['src/secp256k1/*',
                                 'src/leveldb/*',
                                 'src/univalue/*',
                                 'src/crypto/ctaes/*'],
    'clang_format_style'        'src/.clang-format',
    'clang_format_recommended': '3.9.0',
}

###############################################################################
# scoring
###############################################################################


class StyleScore(object):
    """
    A crude calculation to give a percentage rating for adherence to the
    defined style.
    """
    def __init__(self, pre_format, unchanged, added, removed, post_format):
        self.pre_format = pre_format
        self.unchanged = unchanged
        self.added = added
        self.removed = removed
        self.post_format = post_format
        self.score = (100.0 if (added + removed) == 0 else
                      min(abs(1.0 - (float(pre_format - unchanged) /
                                     float(pre_format))) * 100, 99.0))

    def __str__(self):
        return (" +--------+         +------------+--------+---------+--------"
                "---+-------------+\n"
                " | score  |         | pre-format |  added | removed | unchang"
                "ed | post-format |\n"
                " +--------+ +-------+------------+--------+---------+--------"
                "---+-------------+\n"
                " | %3.2f%% | | lines | %10d | %6d | %7d | %9d | %11d |\n"
                " +--------+ +-------+------------+--------+---------+--------"
                "---+-------------+\n" % (self.score, self.pre_format,
                                          self.added, self.removed,
                                          self.unchanged, self.post_format))

    def __float__(self):
        return self.score

    def in_range(self, lower, upper):
        # inclusive
        return (float(self.score) >= lower) and (float(self.score) <= upper)


###############################################################################
# gather file and diff info
###############################################################################

DIFFER = difflib.Differ()


class ClangFormatFileInfo(FileInfo):
    """
    Obtains and represents the information regarding a single file obtained
    from clang-format.
    """
    def __init__(self, repository, file_path, clang_format, force):
        super().__init__(repository, file_path)
        self.clang_format = clang_format
        self.force = force

    def read(self):
        super().read()
        self['formatted'] = (
            self.clang_format.read_formatted_file(self['file_path']))
        self._exit_if_parameters_unsupported()
        self.set_write_content(self['formatted'])

    def _exit_if_parameters_unsupported(self):
        if self.force:
            return
        rejected_parameters = self.clang_format.style.rejected_parameters
        if len(rejected_parameters) > 0:
            r = Report()
            r.add_red("\nERROR: ")
            r.add("clang-format version %s does not support all parameters "
                  "given in\n%s\n\n" % (self.clang_format.binary_version,
                                        self.clang_format.style))
            r.add("Unsupported parameters:\n")
            for parameter in rejected_parameters:
                r.add("\t%s\n" % parameter)
            # The applied formating has subtle differences that vary between
            # major releases of clang-format. The recommendation should
            # probably follow the latest widely-available stable release.
            r.add("\nUsing clang-format version %s or higher is recommended\n"
                  % REPO_INFO['clang_format_recommended'])
            r.add("Use the --force option to override and proceed anyway.\n\n")
            r.flush()
            sys.exit("*** missing clang-format support.")

    def _sum_lines_of_type(self, diff):
        def classify_diff_lines(diff):
            for l in diff:
                if l.startswith('  '):
                    yield 1, 0, 0
                elif l.startswith('+ '):
                    yield 0, 1, 0
                elif l.startswith('- '):
                    yield 0, 0, 1

        return (sum(c) for c in zip(*classify_diff_lines(diff)))

    def compute(self):
        self['matching'] = self['content'] == self['formatted']
        self['formatted_md5'] = (
            hashlib.md5(self['formatted'].encode('utf-8')).hexdigest())
        pre_format_lines = self['content'].splitlines()
        post_format_lines = self['formatted'].splitlines()
        self['pre_format_lines'] = len(pre_format_lines)
        self['post_format_lines'] = len(post_format_lines)
        start_time = time.time()
        diff = DIFFER.compare(pre_format_lines, post_format_lines)
        (self['unchanged_lines'],
         self['added_lines'],
         self['removed_lines']) = self._sum_lines_of_type(diff)
        self['score'] = StyleScore(self['pre_format_lines'],
                                   self['unchanged_lines'],
                                   self['added_lines'],
                                   self['removed_lines'],
                                   self['post_format_lines'])
        self['diff_time'] = time.time() - start_time


###############################################################################
# cmd base class
###############################################################################

class ClangFormatCmd(FileContentCmd):
    """
    Common base class for the commands in this script.
    """
    def __init__(self, repository, jobs, target_fnmatches, json, clang_format,
                 force):
        super().__init__(repository, jobs, SOURCE_FILES, REPO_INFO['subtrees'],
                         target_fnmatches, json)
        self.clang_format = clang_format
        self.force = force

    def _file_info_list(self):
        return [ClangFormatFileInfo(self.repository, f, self.clang_format,
                                    self.force)
                for f in self.files_targeted]


###############################################################################
# report cmd
###############################################################################

class ReportCmd(ClangFormatCmd):
    """
    'report' subcommand class.
    """
    def __init__(self, repository, jobs, target_fnmatches, json, clang_format):
        super().__init__(repository, jobs, target_fnmatches, json,
                         clang_format, True)

    def _cumulative_md5(self):
        # nothing fancy, just hash all the hashes
        h = hashlib.md5()
        for f in self.file_infos:
            h.update(f['formatted_md5'].encode('utf-8'))
        return h.hexdigest()

    def _files_in_ranges(self):
        files_in_ranges = {}
        ranges = [(90, 99), (80, 89), (70, 79), (60, 69), (50, 59), (40, 49),
                  (30, 39), (20, 29), (10, 19), (0, 9)]
        for lower, upper in ranges:
            files_in_ranges['%2d%%-%2d%%' % (lower, upper)] = (
                sum(1 for f in self.file_infos if
                    f['score'].in_range(lower, upper)))
        return files_in_ranges

    def _analysis(self):
        a = super()._analysis()
        file_infos = self.file_infos
        a['clang_format_path'] = self.clang_format.binary_path
        a['clang_format_version'] = str(self.clang_format.binary_version)
        a['clang_style_path'] = str(self.clang_format.style_path)
        a['rejected_parameters'] = self.clang_format.style.rejected_parameters
        a['jobs'] = self.jobs
        a['elapsed_time'] = self.elapsed_time
        a['pre_format_lines'] = sum(f['pre_format_lines'] for f in file_infos)
        a['added_lines'] = sum(f['added_lines'] for f in file_infos)
        a['removed_lines'] = sum(f['removed_lines'] for f in file_infos)
        a['unchanged_lines'] = sum(f['unchanged_lines'] for f in file_infos)
        a['post_format_lines'] = sum(f['post_format_lines'] for f in
                                     file_infos)
        score = StyleScore(a['pre_format_lines'], a['unchanged_lines'],
                           a['added_lines'], a['removed_lines'],
                           a['post_format_lines'])
        a['style_score'] = float(score)
        a['slowest_diffs'] = [{'file_path': f['file_path'],
                               'diff_time': f['diff_time']} for f in
                              file_infos if f['diff_time'] > 1.0]
        a['matching'] = sum(1 for f in file_infos if f['matching'])
        a['not_matching'] = sum(1 for f in file_infos if not f['matching'])
        a['formatted_md5'] = self._cumulative_md5()
        a['files_in_ranges'] = self._files_in_ranges()
        return a

    def _human_print(self):
        super()._human_print()
        r = self.report
        a = self.results
        r.add("clang-format bin:         %s\n" % a['clang_format_path'])
        r.add("clang-format version:     %s\n" % a['clang_format_version'])
        r.add("Using style in:           %s\n" % a['clang_style_path'])
        r.separator()
        if len(a['rejected_parameters']) > 0:
            r.add_red("WARNING")
            r.add(" - This version of clang-format does not support the "
                  "following style\nparameters, so they were not used:\n\n")
            for param in a['rejected_parameters']:
                r.add("%s\n" % param)
            r.separator()
        r.add("Parallel jobs for diffs:   %d\n" % a['jobs'])
        r.add("Elapsed time:              %.02fs\n" % a['elapsed_time'])
        if len(a['slowest_diffs']) > 0:
            r.add("Slowest diffs:\n")
            for slow in a['slowest_diffs']:
                r.add("%6.02fs for %s\n" % (slow['diff_time'],
                                            slow['file_path']))
        r.separator()
        r.add("Files scoring 100%%:        %8d\n" % a['matching'])
        r.add("Files scoring <100%%:       %8d\n" % a['not_matching'])
        r.add("Formatted content MD5:      %s\n" % a['formatted_md5'])
        r.separator()
        for score_range in reversed(sorted(a['files_in_ranges'].keys())):
            r.add("Files scoring %s:        %4d\n" % (
                score_range, a['files_in_ranges'][score_range]))
        r.separator()
        r.add("Overall scoring:\n\n")
        score = StyleScore(a['pre_format_lines'], a['unchanged_lines'],
                           a['added_lines'], a['removed_lines'],
                           a['post_format_lines'])
        r.add(str(score))
        r.separator()
        r.flush()


def add_report_cmd(subparsers):
    def exec_report_cmd(options):
        ReportCmd(options.repository, options.jobs, options.target_fnmatches,
                  options.json, options.clang_format).exec()

    report_help = ("Produces a report with the analysis of the selected"
                   "targets taken as a group.")
    parser = subparsers.add_parser('report', help=report_help)
    parser.set_defaults(func=exec_report_cmd)
    add_jobs_arg(parser)
    add_json_arg(parser)
    add_clang_format_args(parser)
    add_git_tracked_targets_arg(parser)


###############################################################################
# check cmd
###############################################################################

class CheckCmd(ClangFormatCmd):
    """
    'check' subcommand class.
    """
    def __init__(self, repository, jobs, target_fnmatches, json, clang_format,
                 force):
        super().__init__(repository, jobs, target_fnmatches, json,
                         clang_format, force)

    def _analysis(self):
        a = super()._analysis()
        a['failures'] = [{'file_path':         f['file_path'],
                          'style_score':       float(f['score']),
                          'pre_format_lines':  f['pre_format_lines'],
                          'added_lines':       f['added_lines'],
                          'removed_lines':     f['removed_lines'],
                          'unchanged_lines':   f['unchanged_lines'],
                          'post_format_lines': f['post_format_lines']}
                         for f in self.file_infos if not f['matching']]
        return a

    def _human_print(self):
        super()._human_print()
        r = self.report
        a = self.results
        for f in a['failures']:
            r.add("A code format issue was detected in ")
            r.add_red("%s\n\n" % f['file_path'])
            score = StyleScore(f['pre_format_lines'], f['unchanged_lines'],
                               f['added_lines'], f['removed_lines'],
                               f['post_format_lines'])
            r.add(str(score))
            r.separator()
        if len(a['failures']) == 0:
            r.add_green("No format issues found!\n")
        else:
            r.add_red("These files can be formatted by running:\n\n")
            r.add("\t$ clang_format.py format [option [option ...]] "
                  "[file [file ...]]\n\n")
        r.separator()
        r.flush()

    def _shell_exit(self):
        return (0 if len(self.results) == 0 else
                "*** code formatting issue found")


def exec_check_cmd(options):
    CheckCmd(options.repository, options.jobs, options.target_fnmatches,
             options.json, options.clang_format, options.force).exec()


def add_check_cmd(subparsers):
    def exec_check_cmd(options):
        CheckCmd(options.repository, options.jobs, options.target_fnmatches,
                 options.json, options.clang_format, options.force).exec()

    check_help = ("Validates that the selected targets match the style, gives "
                  "a per-file report and returns a non-zero bash status if "
                  "there are any format issues discovered.")
    parser = subparsers.add_parser('check', help=check_help)
    parser.set_defaults(func=exec_check_cmd)
    add_jobs_arg(parser)
    add_json_arg(parser)
    add_force_arg(parser)
    add_clang_format_args(parser)
    add_git_tracked_targets_arg(parser)


###############################################################################
# format cmd
###############################################################################

class FormatCmd(ClangFormatCmd):
    """
    'format' subcommand class.
    """
    def __init__(self, repository, target_fnmatches, clang_format, force):
        super().__init__(repository, 1, target_fnmatches, False, clang_format,
                         force)

    def _compute_file_infos(self):
        pass

    def _analysis(self):
        return None

    def _human_print(self):
        pass

    def _json_print(self):
        pass

    def _write_files(self):
        self.file_infos.write_all()


def add_format_cmd(subparsers):
    def exec_format_cmd(options):
        FormatCmd(options.repository, options.target_fnmatches,
                  options.clang_format, options.force).exec()

    format_help = ("Applies the style formatting to the target files.")
    parser = subparsers.add_parser('format', help=format_help)
    parser.set_defaults(func=exec_format_cmd)
    add_force_arg(parser)
    add_clang_format_args(parser)
    add_git_tracked_targets_arg(parser)


###############################################################################
# UI
###############################################################################


if __name__ == "__main__":
    description = ("A utility for invoking clang-format to look at the C++ "
                   "code formatting in the repository. It produces "
                   "reports of style metrics and also can apply formatting.")
    parser = argparse.ArgumentParser(description=description)
    subparsers = parser.add_subparsers()
    add_report_cmd(subparsers)
    add_check_cmd(subparsers)
    add_format_cmd(subparsers)
    options = parser.parse_args()
    options.clang_format = (
        clang_format_from_options(options, REPO_INFO['clang_format_style']))
    options.func(options)
