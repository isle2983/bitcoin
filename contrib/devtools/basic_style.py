#!/usr/bin/env python3
# Copyright (c) 2017 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import re
import fnmatch
import sys
import subprocess
import datetime
import os
import itertools

###############################################################################
# style rules
###############################################################################


STYLE_RULES = [
    {'title'  : 'No tabstops',
     'applies': ['*.c', '*.cpp', '*.h', '*.py', '*.sh'],
     'regex'  : '\t' ,
     'fix'    : '    ' },
    {'title'  : 'No trailing whitespace on a line',
     'applies': ['*.c', '*.cpp', '*.h', '*.py', '*.sh'],
     'regex'  : ' \n',
     'fix'    : '\n' },
    {'title'  : 'No more than three consecutive newlines',
     'applies': ['*.c', '*.cpp', '*.h', '*.py', '*.sh'],
     'regex'  : '\n\n\n\n',
     'fix'    : '\n\n\n',
    },
    {'title'  : 'Do not end a line with a semicolon',
     'applies': ['*.py'],
     'regex'  : ';\n',
     'fix'    : '\n',
    },
    {'title'  : 'Do not end a line with two semicolons',
     'applies': ['*.c', '*.cpp', '*.h'],
     'regex'  : ';;\n',
     'fix'    : ';\n',
    },
]

for rule in STYLE_RULES:
    rule['regex_compiled'] = re.compile(rule['regex'])
    rule['fix_compiled'] = re.compile(rule['fix'])
    rule['applies_compiled'] = re.compile('|'.join([fnmatch.translate(f) for f
                                                    in rule['applies']]))


###############################################################################
# files we want exempt from these rules
###############################################################################


ALWAYS_IGNORE = [# files in subtrees:
                 'src/secp256k1/*',
                 'src/leveldb/*',
                 'src/univalue/*',
                 'src/crypto/ctaes/*',
                 # files that are auto generated:
                 'src/qt/paymentrequest.pb.cc',
                 'src/qt/bitcoinstrings.cpp',
                ]

ALWAYS_IGNORE_COMPILED = re.compile('|'.join([fnmatch.translate(match)
                                              for match in ALWAYS_IGNORE]))

###############################################################################
# obtain list of files in repo to check that match extensions
###############################################################################


GIT_LS_CMD = 'git ls-files'


def git_ls():
    out = subprocess.check_output(GIT_LS_CMD.split(' '))
    return [f for f in out.decode("utf-8").split('\n') if f != '']


APPLIES_FILTER = set(itertools.chain(*[r['applies'] for r in STYLE_RULES]))
APPLIES_FILTER_COMPILED = re.compile('|'.join([fnmatch.translate(a) for a in
                                               APPLIES_FILTER]))


def filename_is_to_be_examined(filename):
    return (APPLIES_FILTER_COMPILED.match(filename) and not
            ALWAYS_IGNORE_COMPILED.match(filename))


def get_filenames_to_examine(full_file_list):
    return sorted([filename for filename in full_file_list if
                   filename_is_to_be_examined(filename)])


###############################################################################
# file IO
###############################################################################


def read_file(filename):
    file = open(os.path.abspath(filename), 'r')
    contents = file.read()
    file.close()
    return contents


def write_file(filename, contents):
    file = open(os.path.abspath(filename), 'w')
    file.write(contents)
    file.close()


###############################################################################
# get file info
###############################################################################


def find_match_line(contents, match, filename):
    line = {}
    contents_before_match = contents[:match.start()]
    line['number'] = contents_before_match.count('\n') + 1

    line_start = contents_before_match.rfind('\n') + 1
    line['contents'] = contents[line_start:match.end()]
    line['character'] = match.start() - line_start + 1

    return line


def evaluate_rule(rule, contents, filename):
    evaluation = {}

    evaluation['matches'] = [match for match in
                             rule['regex_compiled'].finditer(contents) if
                             match is not None]
    evaluation['lines'] = [find_match_line(contents, match, filename) for match
                           in evaluation['matches']]
    evaluation['pass'] = len(evaluation['matches']) == 0
    return evaluation


def gather_file_info(filename):
    file_info = {}
    file_info['filename'] = filename
    file_info['contents'] = read_file(filename)
    file_info['rules'] = [r for r in STYLE_RULES if
                          r['applies_compiled'].match(filename)]
    file_info['rules_not_covering'] = [r for r in STYLE_RULES if not
                                       r['applies_compiled'].match(filename)]

    for rule in file_info['rules']:
        file_info[rule['title']] = evaluate_rule(rule, file_info['contents'],
                                                 filename)
    return file_info


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


###############################################################################
# report execution
###############################################################################


def report_filenames(file_infos):
    if len(file_infos) == 0:
        return
    report('\t')
    report('\n\t'.join([file_info['filename'] for file_info in file_infos]))
    report('\n')


def report_summary(file_infos, full_file_list):
    report("%4d files tracked according to '%s'\n" %
           (len(full_file_list), GIT_LS_CMD))
    report("%4d files examined according to STYLE_RULES and ALWAYS_IGNORE "
           "fnmatch rules\n" % len(file_infos))


def report_rule(rule, file_infos):
    covered = [file_info for file_info in file_infos if
               rule in file_info['rules']]
    not_covered = [file_info for file_info in file_infos if
                   rule in file_info['rules_not_covering']]

    passed = [file_info for file_info in covered if
              file_info[rule['title']]['pass']]
    failed = [file_info for file_info in covered if not
              file_info[rule['title']]['pass']]

    report('Rule title: "%s"\n' % rule['title'])
    report('File extensions covered by rule:    %s\n' % rule['applies'])
    report("Files covered by rule:             %4d\n" % len(covered))
    report("Files not covered by rule:         %4d\n" % len(not_covered))
    report("Files passed:                      %4d\n" % len(passed))
    report("Files failed:                      %4d\n" % len(failed))
    report_filenames(failed)


def print_report(file_infos, full_file_list):
    report(SEPARATOR)
    report_summary(file_infos, full_file_list)
    for rule in STYLE_RULES:
        report(SEPARATOR)
        report_rule(rule, file_infos)
    report(SEPARATOR)
    print(''.join(REPORT), end="")


def exec_report(base_directory):
    original_cwd = os.getcwd()
    os.chdir(base_directory)
    full_file_list = git_ls()
    file_infos = [gather_file_info(filename) for filename in
                  get_filenames_to_examine(full_file_list)]
    print_report(file_infos, full_file_list)
    os.chdir(original_cwd)


###############################################################################
# report cmd
###############################################################################


REPORT_USAGE = """
TODO

Usage:
    $ ./basic_style.py report <base_directory>

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
# check execution
###############################################################################


def get_failures(file_infos):
    failures = []
    for file_info in file_infos:
        for rule in STYLE_RULES:
            if (rule['title'] in file_info and not
                file_info[rule['title']]['pass']):
                failure = {}
                failure['filename'] = file_info['filename']
                failure['contents'] = file_info['contents']
                failure['title'] = rule['title']
                failure['lines'] = file_info[rule['title']]['lines']
                failure['rule'] = rule
                failures.append(failure)
    return failures


def report_failure(failure):
    report("An issue was found with ")
    red_report("%s\n" % failure['filename'])
    report('Rule: "%s"\n\n' % failure['title'])
    for line in failure['lines']:
        report('line %d:\n' % line['number'])
        report("%s" % line['contents'])
        report(' ' * (line['character'] - 1))
        red_report("^\n")


def print_check_report(file_infos, full_file_list, failures):
    report(SEPARATOR)
    report_summary(file_infos, full_file_list)

    for failure in failures:
        report(SEPARATOR)
        report_failure(failure)

    report(SEPARATOR)
    if len(failures) == 0:
        green_report("No basic style issues found!\n")
    else:
        red_report("These issues can be fixed automatically by running:\n")
        report("$ contrib/devtools/basic_style.py fix <base_directory>\n")
    report(SEPARATOR)
    print(''.join(REPORT), end="")


def exec_check(base_directory):
    original_cwd = os.getcwd()
    os.chdir(base_directory)
    full_file_list = git_ls()
    file_infos = [gather_file_info(filename) for filename in
                  get_filenames_to_examine(full_file_list)]
    failures = get_failures(file_infos)
    print_check_report(file_infos, full_file_list, failures)
    os.chdir(original_cwd)
    if len(failures) > 0:
        sys.exit("*** Basic style issues found!")


###############################################################################
# check cmd
###############################################################################


CHECK_USAGE = """
TODO

Usage:
    $ ./basic_style.py check <base_directory>

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

    exec_check(base_directory)


###############################################################################
# fix execution
###############################################################################


def fix_contents(contents, regex, fix):
    while True:
        contents, subs = regex.subn(fix, contents)
        if subs == 0:
            break
    return contents


def fix_failures(failures):
    for failure in failures:
        contents = fix_contents(failure['contents'],
                                failure['rule']['regex_compiled'],
                                failure['rule']['fix'])
        write_file(failure['filename'], contents)


def exec_fix(base_directory):
    original_cwd = os.getcwd()
    os.chdir(base_directory)
    full_file_list = git_ls()
    file_infos = [gather_file_info(filename) for filename in
                  get_filenames_to_examine(git_ls())]

    failures = get_failures(file_infos)
    fix_failures(failures)
    os.chdir(original_cwd)


###############################################################################
# fix cmd
###############################################################################


FIX_USAGE = """
TODO

Usage:
    $ ./basic_style.py fix <base_directory>

Arguments:
    <base_directory> - The base directory of a bitcoin core source code
    repository.
"""


def fix_cmd(argv):
    if len(argv) != 3:
        sys.exit(CHECK_USAGE)

    base_directory = argv[2]
    if not os.path.exists(base_directory):
        sys.exit("*** bad <base_directory>: %s" % base_directory)

    exec_fix(base_directory)


###############################################################################
# UI
###############################################################################


USAGE = """
basic_style.py - utilities for checking basic style in source code files.

Usage:
    $ ./basic_style.py <subcommand>

Subcommands:
    report
    check

To see subcommand usage, run them without arguments.
"""

SUBCOMMANDS = ['report', 'check', 'fix']


if __name__ == "__main__":
    if len(sys.argv) == 1:
        sys.exit(USAGE)
    if sys.argv[1] not in SUBCOMMANDS:
        sys.exit(USAGE)
    if sys.argv[1] == 'report':
        report_cmd(sys.argv)
    elif sys.argv[1] == 'check':
        check_cmd(sys.argv)
    elif sys.argv[1] == 'fix':
        fix_cmd(sys.argv)
