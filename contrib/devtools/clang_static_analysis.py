#!/usr/bin/env python3
# Copyright (c) 2017 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import sys
import os
import subprocess
import time
import plistlib

# Use the installed scan-binary by default:
SCAN_BUILD_BINARY = "scan-build"
# Alternatively, use a specific binary like so:
# SCAN_BUILD_BINARY = "/usr/share/clang/scan-build-3.4/scan-build"

RESULT_DIR = "/tmp/bitcoin-scan-build/"
CLEAN_LOG = "%smake_clean.log" % RESULT_DIR
BUILD_LOG = "%sscan_build.log" % RESULT_DIR

MAKE_JOBS = "-j16"
MAKE_CMD = "make %s" % MAKE_JOBS
MAKE_CLEAN_CMD = "make clean"

SCAN_BUILD_CMD = "%%s -k -plist-html --keep-empty -o %s %s" % (RESULT_DIR,
                                                               MAKE_CMD)

###############################################################################
# cmd helpers
###############################################################################


def get_cmd_output(cmd):
    out = subprocess.check_output(cmd.split(' '))
    return [l for l in out.decode("utf-8").split('\n') if l != '']


def call_cmd(cmd, outfile):
    file = open(os.path.abspath(outfile), 'w')
    if subprocess.call(cmd.split(' '), stdout=file, stderr=file) != 0:
        sys.exit("*** '%s' returned a non-zero status" % cmd)
    file.close()


###############################################################################
# environment helpers
###############################################################################


def make_result_dir():
    if not os.path.exists(RESULT_DIR):
        os.makedirs(RESULT_DIR)


def locate_scan_build():
    out_lines = get_cmd_output('which %s' % SCAN_BUILD_BINARY)
    if len(out_lines) == 0:
        sys.exit("*** could not find binary '%s'" % SCAN_BUILD_BINARY)
    binary = os.path.realpath(out_lines[0])
    print("using binary: %s" % binary)
    return binary


def assert_has_makefile(base_directory):
    if not os.path.exists("Makefile"):
        sys.exit("*** no Makefile found in %s. You must ./autogen.sh and/or "
                 "./configure first" % base_directory)

def locate_result_directory():
    # Scan-build puts results in a directory where the directory name is a
    # timestamp. e.g. /tmp/bitcoin-scan-build/2017-01-23-115243-901-1
    # We want the most recent directory, so we sort and return the highest
    # directory name.
    subdir = sorted([d for d in os.listdir(RESULT_DIR) if
                     os.path.isdir(os.path.join(RESULT_DIR, d))])[-1]
    return os.path.join(RESULT_DIR, subdir)


###############################################################################
# execution helpers
###############################################################################


def make_clean():
    print("Running:             %s" % MAKE_CLEAN_CMD)
    print("stderr/stdout to:    %s" % CLEAN_LOG)
    call_cmd(MAKE_CLEAN_CMD, CLEAN_LOG)


def run_scan_build(binary):
    cmd = SCAN_BUILD_CMD % binary
    print("Running:             %s" % cmd)
    print("stderr/stdout to:    %s" % BUILD_LOG)
    print("This might take a while..." )
    call_cmd(cmd, BUILD_LOG)
    print("Done.")


###############################################################################
# report helpers
###############################################################################


SEPARATOR = '-' * 80 + '\n'
REPORT = []


def report(string):
    REPORT.append(string)


GREEN = '\033[92m'
RED = '\033[91m'
ENDC = '\033[0m'


def red_report(string):
    report(RED + string + ENDC)


def green_report(string):
    report(GREEN + string + ENDC)


def flush_report():
    print(''.join(REPORT), end="")


###############################################################################
# get issues
###############################################################################

def plist_is_relevant(plist):
    return len(plist['files']) > 0


def plist_to_issue(plist):
    return {'type':        plist['diagnostics'][0]['type'],
            'description': plist['diagnostics'][0]['description'],
            'line':        plist['diagnostics'][0]['location']['line'],
            'col':         plist['diagnostics'][0]['location']['col'],
            'file': plist['files'][plist['diagnostics'][0]['location']['file']],
           }

def get_issues(directory):
    plist_files = [os.path.join(directory, f) for f in os.listdir(directory) if
                   f.endswith('.plist')]
    parsed_plists = [plistlib.readPlist(plist_file) for plist_file in
                     plist_files]

    relevant_plists = [plist for plist in parsed_plists if
                       plist_is_relevant(plist)]

    return [plist_to_issue(plist) for plist in relevant_plists]

###############################################################################
# report execution
###############################################################################

def generate_results(binary):
    #make_clean()
    #run_scan_build(binary)

    # TODO put this in run_scan_build:
    directory = locate_result_directory()
    print("Results in:          %s" % directory)
    return directory

def report_issue(issue):
    report("\tType:         %s\n" % issue['type'])
    report("\tDescription:  %s\n" % issue['description'])
    report("\tLocation:     %s:%d:%d\n" % (issue['file'], issue['line'],
                                           issue['col']))

def report_result_directory(start_time, directory):
    issues = get_issues(directory)
    elapsed_time = time.time() - start_time
    report(SEPARATOR)
    report("Took %.2f seconds to analyze with scan-build\n" % elapsed_time)
    report("Found %d issues:\n" % len(issues))
    idx = 0
    for issue in issues:
        report("%d:\n" % idx)
        report_issue(issue)
        idx = idx + 1
    report(SEPARATOR)
    report("Full details can be viewed in a browser by running:\n")
    report("    $ scan-view %s\n" % directory)
    report(SEPARATOR)
    flush_report()


def exec_report(base_directory):
    start_time = time.time()
    make_result_dir()
    original_cwd = os.getcwd()
    os.chdir(base_directory)
    assert_has_makefile(base_directory)
    binary = locate_scan_build()
    directory = generate_results(binary)
    report_result_directory(start_time, directory)
    os.chdir(original_cwd)


###############################################################################
# report cmd
###############################################################################


REPORT_USAGE = """
TODO

Usage:
    $ ./clang_static_analysis.py report <base_directory>

Arguments:
    <base_directory> - The base directory of a bitcoin core source code
    repository.
"""


def report_cmd(argv):
    if len(argv) != 3:
        sys.exit(REPORT_USAGE)

    base_directory = argv[2]
    if not os.path.exists(base_directory):
        sys.exit("*** bad <base_directory>: %s" % base_directory)

    exec_report(base_directory)


###############################################################################
# check cmd
###############################################################################


CHECK_USAGE = """
TODO

Usage:
    $ ./clang_static_analysis.py check <base_directory>

Arguments:
    <base_directory> - The base directory of a bitcoin core source code
    repository.
"""


def check_cmd(argv):
    if len(argv) != 3:
        sys.exit(CHECK_USAGE)

    base_directory = argv[2]
    if not os.path.exists(base_directory):
        sys.exit("*** bad <base_directory>: %s" % base_directory)

    #exec_check(base_directory)

###############################################################################
# UI
###############################################################################


USAGE = """
clang_static_analysis.py - utilities for checking basic style in source code
files.

Usage:
    $ ./clang_static_analysis.py <subcommand>

Subcommands:
    report
    check

To see subcommand usage, run them without arguments.
"""

SUBCOMMANDS = ['report', 'check']


if __name__ == "__main__":
    if len(sys.argv) == 1:
        sys.exit(USAGE)
    if sys.argv[1] not in SUBCOMMANDS:
        sys.exit(USAGE)
    if sys.argv[1] == 'report':
        report_cmd(sys.argv)
    elif sys.argv[1] == 'check':
        check_cmd(sys.argv)
