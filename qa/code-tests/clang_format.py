#!/usr/bin/env python3
# Copyright (c) 2017 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import sys
import os
import subprocess
import time
import argparse
import re
import fnmatch
import difflib
import hashlib
from multiprocessing import Pool
from framework.report import Report
from framework.action import ReadableFileAction
from framework.clang import ClangDirectoryAction
from framework.clang import ClangFind
from framework.clang import ClangFormat
from framework.file_filter import FileFilter
from framework.file import read_file, write_file
from framework.git import GitTrackedTargetsAction

R = Report()

###############################################################################
# settings for the set of files that this applies to
###############################################################################

REPO_INFO = {
    'source_files':       ['*.cpp', '*.h'],
    'subtrees_to_ignore': ['src/secp256k1/*',
                           'src/leveldb/*',
                           'src/univalue/*',
                           'src/crypto/ctaes/*'],
    'style_file':         'src/.clang-format',
}

###############################################################################
# scoring
###############################################################################


def style_score(pre_format, unchanged, added, removed):
    # A crude calculation to give a percentage rating for adherence to the
    # defined style.
    if (added + removed) == 0:
        return 100
    return min(int(abs(1 - (float(pre_format - unchanged) /
                            float(pre_format))) * 100), 99)


def scoreboard(score, pre_format, added, removed, unchanged, post_format):
    return (" +-------+          +------------+--------+---------+-----------+"
            "-------------+\n"
            " | score |          | pre-format |  added | removed | unchanged |"
            " post-format |\n"
            " +-------+  +-------+------------+--------+---------+-----------+"
            "-------------+\n"
            " | %3d%%  |  | lines | %10d | %6d | %7d | %9d | %11d |\n"
            " +-------+  +-------+------------+--------+---------+-----------+"
            "-------------+\n" % (score, pre_format, added, removed,
                                  unchanged, post_format))


###############################################################################
# gather file and diff info
###############################################################################


def classify_diff_lines(diff):
    for l in diff:
        if l.startswith('  '):
            yield 1, 0, 0
        elif l.startswith('+ '):
            yield 0, 1, 0
        elif l.startswith('- '):
            yield 0, 0, 1


def sum_lines_of_type(diff):
    return (sum(c) for c in zip(*classify_diff_lines(diff)))


def gather_file_info(opts, filename):
    start = time.time()
    file_info = {}
    file_info['filename'] = filename
    file_info['contents'] = read_file(filename)
    file_info['formatted'] = opts.clang_format.read_formatted_file(filename)
    file_info['matching'] = (file_info['contents'] == file_info['formatted'])
    file_info['formatted_md5'] = (
        hashlib.md5(file_info['formatted'].encode('utf-8')).hexdigest())
    return file_info


DIFFER = difflib.Differ()


def compute_diff_info(file_info):
    pre_format_lines = file_info['contents'].splitlines()
    post_format_lines = file_info['formatted'].splitlines()
    file_info['pre_format_lines'] = len(pre_format_lines)
    file_info['post_format_lines'] = len(post_format_lines)
    start_time = time.time()
    diff = DIFFER.compare(pre_format_lines, post_format_lines)
    (file_info['unchanged_lines'],
     file_info['added_lines'],
     file_info['removed_lines']) = sum_lines_of_type(diff)
    file_info['diff_time'] = time.time() - start_time
    file_info['score'] = style_score(file_info['pre_format_lines'],
                                     file_info['unchanged_lines'],
                                     file_info['added_lines'],
                                     file_info['removed_lines'])
    return file_info


###############################################################################
# warning for old versions of clang-format
###############################################################################


def report_if_parameters_unsupported(opts):
    rejected = opts.clang_format.rejected_parameters()
    if len(rejected) == 0:
        return
    R.separator()
    R.add_red("WARNING")
    R.add(" - This version of clang-format does not support the "
          "following style\nparameters, so they were not used:\n\n")
    for param in rejected:
        R.add("%s\n" % param)


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
        R.add("\nUsing clang-format version 3.9.0 or higher is recommended\n")
        R.add("Use the --force option to override and proceed anyway.\n\n")
        R.flush()
        sys.exit("*** missing clang-format support.")


###############################################################################
# 'report' subcommand execution
###############################################################################


def report_examined_files(opts, git_ls_list):
    R.add("%4d files tracked in repo\n" %
          (len(git_ls_list)))
    scope_list = [p for p in git_ls_list if opts.scope_filter.evaluate(p)]
    R.add("%4d files in scope according to SOURCE_FILES and ALWAYS_IGNORE "
          "settings\n" % len(scope_list))
    target_list = [p for p in git_ls_list if opts.target_filter.evaluate(p)]
    R.add("%4d files examined according to listed targets\n" %
          len(target_list))


def score_in_range_inclusive(score, lower, upper):
    return (score >= lower) and (score <= upper)


def report_files_in_range(file_infos, lower, upper):
    in_range = [file_info for file_info in file_infos if
                score_in_range_inclusive(file_info['score'], lower, upper)]
    R.add("Files %2d%%-%2d%% matching:        %4d\n" % (lower, upper,
                                                        len(in_range)))


def report_files_in_ranges(file_infos):
    ranges = [(90, 99), (80, 89), (70, 79), (60, 69), (50, 59), (40, 49),
              (30, 39), (20, 29), (10, 19), (0, 9)]
    for lower, upper in ranges:
        report_files_in_range(file_infos, lower, upper)


def report_slowest_diffs(file_infos):
    slowest = [file_info for file_info in file_infos if
               file_info['diff_time'] > 1.0]
    if len(slowest) == 0:
        return
    R.add("Slowest diffs:\n")
    for file_info in slowest:
        R.add("%6.02fs for %s\n" % (file_info['diff_time'],
                                    file_info['filename']))


def print_report(opts, elapsed_time, file_infos, git_ls_list):
    pre_format_lines = sum(file_info['pre_format_lines'] for file_info in
                           file_infos)
    added_lines = sum(file_info['added_lines'] for file_info in file_infos)
    removed_lines = sum(file_info['removed_lines'] for file_info in file_infos)
    unchanged_lines = sum(file_info['unchanged_lines'] for file_info in
                          file_infos)
    post_format_lines = sum(file_info['post_format_lines'] for file_info in
                            file_infos)
    score = style_score(pre_format_lines, unchanged_lines, added_lines,
                        removed_lines)
    matching = [file_info for file_info in file_infos if
                file_info['matching']]
    not_matching = [file_info for file_info in file_infos if not
                    file_info['matching']]
    h = hashlib.md5()
    for file_info in file_infos:
        h.update(file_info['formatted_md5'].encode('utf-8'))
    formatted_md5 = h.hexdigest()

    R.separator()
    report_examined_files(opts, git_ls_list)
    R.separator()
    R.add("clang-format bin:         %s\n" % opts.clang_format.binary_path)
    R.add("clang-format version:     %s\n" % opts.clang_format.binary_version)
    R.add("Using style in:           %s\n" % opts.clang_format.style)
    report_if_parameters_unsupported(opts)
    R.separator()
    R.add("Parallel jobs for diffs:   %d\n" % opts.jobs)
    R.add("Elapsed time:              %.02fs\n" % elapsed_time)
    report_slowest_diffs(file_infos)
    R.separator()
    R.add("Files 100%% matching:       %8d\n" % len(matching))
    R.add("Files <100%% matching:      %8d\n" % len(not_matching))
    R.add("Formatted content MD5:      %s\n" % formatted_md5)
    R.separator()
    report_files_in_ranges(file_infos)
    R.separator()
    R.add("\n")
    R.add(scoreboard(score, pre_format_lines, added_lines, removed_lines,
                     unchanged_lines, post_format_lines))
    R.add("\n")
    R.separator()
    R.flush()


def exec_report(opts):
    start_time = time.time()
    git_ls_list = opts.repository.tracked_files()
    file_infos = [gather_file_info(opts, filename) for filename in
                  git_ls_list if opts.target_filter.evaluate(filename)]
    file_infos = Pool(opts.jobs).map(compute_diff_info, file_infos)

    print_report(opts, time.time() - start_time, file_infos, git_ls_list)


###############################################################################
# 'check' subcommand execution
###############################################################################


def get_failures(file_infos):
    return [file_info for file_info in file_infos if not
            file_info['matching']]


def report_failure(failure):
    R.add("A code format issue was detected in ")
    r.add_red("%s\n" % failure['filename'])
    R.add(scoreboard(failure['score'], failure['pre_format_lines'],
                     failure['added_lines'], failure['removed_lines'],
                     failure['unchanged_lines'],
                     failure['post_format_lines']))


def print_check(opts, failures, file_infos, in_scope_file_list,
                full_file_list):
    R.separator()
    report_examined_files(file_infos, in_scope_file_list, full_file_list)
    for failure in failures:
        R.separator()
        report_failure(failure)
    R.separator()
    if len(failures) == 0:
        R.add_green("No format issues found!\n")
    else:
        R.add_red("These files can be auto-formatted by running:\n")
        R.add("$ contrib/devtools/clang_format.py format [target "
              "[target ...]]\n")
    R.separator()


def exec_check(opts):
    full_file_list = git_ls(opts)
    in_scope_file_list = get_filenames_in_scope(full_file_list)
    file_infos = [gather_file_info(opts, filename) for filename in
                  in_scope_file_list if opts.target_regex.match(filename)]
    exit_if_parameters_unsupported(opts)
    file_infos = Pool(opts.jobs).map(compute_diff_info, file_infos)
    failures = get_failures(file_infos)
    print_check(opts, failures, file_infos, in_scope_file_list, full_file_list)
    if len(failures) > 0:
        sys.exit("*** Format issues found!")


###############################################################################
# 'format' subcommand execution
###############################################################################


def exec_format(opts):
    full_file_list = git_ls(opts)
    in_scope_file_list = get_filenames_in_scope(full_file_list)
    file_infos = [gather_file_info(opts, filename) for filename in
                  in_scope_file_list if opts.target_regex.match(filename)]
    exit_if_parameters_unsupported(opts)
    failures = get_failures(file_infos)
    for failure in failures:
        write_file(failure['filename'], failure['formatted'])


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

    # set up file filters
    opts.scope_filter = FileFilter()
    opts.scope_filter.append_include(REPO_INFO['source_files'],
                                     base_path=str(opts.repository))
    opts.scope_filter.append_exclude(REPO_INFO['subtrees_to_ignore'],
                                     base_path=str(opts.repository))

    opts.target_filter = FileFilter()
    opts.target_filter.append_include(REPO_INFO['source_files'],
                                      base_path=str(opts.repository))
    opts.target_filter.append_exclude(REPO_INFO['subtrees_to_ignore'],
                                      base_path=str(opts.repository))
    opts.target_filter.append_include(opts.target_fnmatches,
                                      base_path=str(opts.repository))

    # execute commands
    os.chdir(str(opts.repository))
    if opts.subcommand == 'report':
        exec_report(opts)
    elif opts.subcommand == 'check':
        exec_check(opts)
    else:
        exec_format(opts)
