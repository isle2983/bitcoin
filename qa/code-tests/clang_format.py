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
import json

from framework.report import Report
from framework.action import ReadableFileAction
from framework.clang import ClangDirectoryAction
from framework.clang import ClangFind
from framework.clang import ClangFormat
from framework.file_filter import FileFilter
from framework.git import GitTrackedTargetsAction
from framework.file_info import FileInfo, FileInfos

###############################################################################
# settings for the set of files that this applies to
###############################################################################

REPO_INFO = {
    'source_files':             ['*.cpp', '*.h'],
    'subtrees_to_ignore':       ['src/secp256k1/*',
                                 'src/leveldb/*',
                                 'src/univalue/*',
                                 'src/crypto/ctaes/*'],
    'style_file':               'src/.clang-format',
    'recommended_clang_format': '3.9.0',
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
    def __init__(self, repository, file_path, clang_format):
        super().__init__(repository, file_path)
        self.clang_format = clang_format

    def read(self):
        super().read()
        self['formatted'] = (
            self.clang_format.read_formatted_file(self['file_path']))

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
        self.set_write_content(self['formatted'])
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
# warning for old versions of clang-format
###############################################################################


def exit_if_parameters_unsupported(opts):
    if opts.force:
        return
    if len(opts.unknown_style_params) > 0:
        R.add_red("\nWARNING: ")
        R.add("clang-format version %s does not support all "
              "parameters given in\n%s\n\n" % (opts.bin_version,
                                               opts.style_file))
        R.add("Unsupported parameters:\n")
        for param in opts.unknown_style_params:
            R.add("\t%s\n" % param)
        # The recommendation is from experimentation where it is found that the
        # applied formating has subtle differences that vary between major
        # releases of clang-format. A chosen standard of formatting should
        # probably be based on the latest stable release and that should be the
        # recommendation.
        R.add("\nUsing clang-format version %s or higher is recommended\n",
              REPO_INFO['recommended_clang_format'])
        R.add("Use the --force option to override and proceed anyway.\n\n")
        R.flush()
        sys.exit("*** missing clang-format support.")


###############################################################################
# 'format' subcommand execution
###############################################################################


class FileContentCmd(object):
    def __init__(self, repository, jobs, target_fnmatches, json):
        self.repository = repository
        self.jobs = jobs
        self.json = json
        self.tracked_files = self._get_tracked_files(self.repository)
        self.files_in_scope = list(self._files_in_scope(self.repository,
                                                        self.tracked_files))
        self.files_targeted = list(self._files_targeted(self.repository,
                                                        self.files_in_scope,
                                                        target_fnmatches))
        self.report = Report()

    def _get_tracked_files(self, repository):
        return repository.tracked_files()

    def _scope_filter(self, repository):
        file_filter = FileFilter()
        file_filter.append_include(REPO_INFO['source_files'],
                                   base_path=str(repository))
        file_filter.append_exclude(REPO_INFO['subtrees_to_ignore'],
                                   base_path=str(repository))
        return file_filter

    def _files_in_scope(self, repository, tracked_files):
        file_filter = self._scope_filter(repository)
        return (f for f in tracked_files if file_filter.evaluate(f))

    def _target_filter(self, repository, target_fnmatches):
        file_filter = self._scope_filter(repository)
        file_filter.append_include(target_fnmatches, base_path=repository)
        return file_filter

    def _files_targeted(self, repository, tracked_files, target_fnmatches):
        file_filter = self._target_filter(repository, target_fnmatches)
        return (f for f in tracked_files if file_filter.evaluate(f))


    def _read_and_compute_file_infos(self):
        start_time = time.time()
        self.file_infos = FileInfos(self.jobs, self._get_file_info_list())
        self.file_infos.read_all()
        self.file_infos.compute_all()
        self.elapsed_time = time.time() - start_time

    def _analysis(self):
        a = {}
        a['tracked_files'] = len(self.tracked_files)
        a['files_in_scope'] = len(self.files_in_scope)
        a['files_targeted'] = len(self.files_targeted)
        return a

    def _human_print(self):
        r = self.report
        a = self.results
        r.separator()
        r.add("%4d files tracked in repo\n" % a['tracked_files'])
        r.add("%4d files in scope according to REPO_INFO settings\n" %
              a['files_in_scope'])
        r.add("%4d files examined according to listed targets\n" %
              a['files_targeted'])
        r.separator()

    def _json_print(self):
        print(json.dumps(self.results))

    def _write_files(self):
        pass

    def exec(self):
        self._read_and_compute_file_infos()
        self._write_files()
        self.results = self._analysis()
        self._json_print() if self.json else self._human_print()


class ClangFormatCmd(FileContentCmd):
    def __init__(self, repository, jobs, target_fnmatches, json, clang_format,
                 style_path):
        super().__init__(repository, jobs, target_fnmatches, json)
        self.clang_format = clang_format
        self.style_path = style_path

    def _get_file_info_list(self):
        return [ClangFormatFileInfo(self.repository, f, self.clang_format) for
                f in self.files_targeted]


class ReportCmd(ClangFormatCmd):
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
        a['clang_style_path'] = str(self.style_path)
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
        a['style_scoreboard'] = str(score)
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
        r.add(a['style_scoreboard'])
        r.separator()
        r.flush()


class CheckCmd(ClangFormatCmd):
    def __init__(self, repository, jobs, target_fnmatches, json, force,
                 clang_format, style_path):
        super().__init__(repository, jobs, target_fnmatches, json,
                         clang_format, style_path)
        self.force = force

    def _analysis(self):
        a = super()._analysis()
        a['failures'] = [{'file_path':         f['file_path'],
                          'style_score':       float(f['score']),
                          'style_scoreboard':  str(f['score']),
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
            r.add(f['style_scoreboard'])
            r.separator()
        if len(a['failures']) == 0:
            r.add_green("No format issues found!\n")
        else:
            r.add_red("These files can be auto-formatted by running:\n\n")
            r.add("$ clang_format.py format %s\n" %
                  ' '.join(f['file_path'] for f in a['failures']))
        r.separator()
        r.flush()


class FormatCmd(ClangFormatCmd):
    def __init__(self, repository, jobs, target_fnmatches, json, force,
                 clang_format, style_path):
        super().__init__(repository, jobs, target_fnmatches, json,
                         clang_format, style_path)
        self.force = force

    def _analysis(self):
        return None

    def _human_print(self):
        pass

    def _json_print(self):
        pass

    def _write_files(self):
        self.file_infos.write_all()


###############################################################################
# UI
###############################################################################


if __name__ == "__main__":
    # parse arguments
    description = ("A utility for invoking clang-format to observe the state "
                   "of C++ code formatting in the repository. It produces "
                   "reports of style metrics and also can apply formatting.")
    parser = argparse.ArgumentParser(description=description)
    b_help = ("The path to the clang dirctory or binary to be used for "
              "clang-format. (default=The clang-format installed in PATH with "
              "the highest version number)")
    parser.add_argument("-b", "--bin-path", type=str,
                        action=ClangDirectoryAction, help=b_help)
    sf_help = ("The path to the style file to be used. (default=The "
               "src/.clang_format file of the repository which holds the "
               "targets)")
    parser.add_argument("-s", "--style-file", type=str,
                        action=ReadableFileAction, help=sf_help)
    j_help = ("Parallel jobs for computing diffs. (default=4)")
    parser.add_argument("-j", "--jobs", type=int, default=4, help=j_help)
    f_help = ("Force proceeding with 'check' or 'format' if clang-format "
              "doesn't support all parameters in the style file. "
              "(default=False)")
    parser.add_argument("-f", "--force", action='store_true', help=f_help)
    s_help = ("Selects the action to be taken. 'report' produces a report "
              "with analysis of the selected files taken as a group. 'check' "
              "validates that the selected files match the style and gives "
              "a per-file report and returns a non-zero bash status if there "
              "are any format issues discovered. 'format' applies the style "
              "formatting to the selected files.")
    parser.add_argument("subcommand", type=str,
                        choices=['report', 'check', 'format'], help=s_help)
    t_help = ("A list of files and/or directories that select the subset of "
              "files for this action. If a directory is given as a target, "
              "all files contained in it and its subdirectories are "
              "recursively selected. All targets must be tracked in the same "
              "git repository clone. (default=The current directory)")
    parser.add_argument("target", type=str, action=GitTrackedTargetsAction,
                        nargs='*', default=['.'], help=t_help)
    opts = parser.parse_args()

    # find clang-format binary and style
    binary = (opts.clang_executables['clang-format'] if
              hasattr(opts, 'clang_executables') else
              ClangFind().best('clang-format'))
    style_path = (opts.style_file if opts.style_file else
                  os.path.join(str(opts.repository), REPO_INFO['style_file']))
    opts.clang_format = ClangFormat(binary, style_path)

    # execute commands
    if opts.subcommand == 'report':
        ReportCmd(opts.repository, opts.jobs, opts.target_fnmatches,
                  False, opts.clang_format, style_path).exec()
    elif opts.subcommand == 'check':
        CheckCmd(opts.repository, opts.jobs, opts.target_fnmatches, False,
                 False, opts.clang_format, style_path).exec()
    else:
        FormatCmd(opts.repository, opts.jobs, opts.target_fnmatches, True,
                  False, opts.clang_format, style_path).exec()
