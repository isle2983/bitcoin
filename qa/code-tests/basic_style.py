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
from framework.style import StyleDiff


REPO_INFO = {
    'subtrees': ['src/secp256k1/*',
                 'src/leveldb/*',
                 'src/univalue/*',
                 'src/crypto/ctaes/*'],
}

###############################################################################
# style rules
###############################################################################

STYLE_RULES = [
    {'title':   'No tabstops',
     'applies': ['*.c', '*.cpp', '*.h', '*.py', '*.sh'],
     'regex':   '\t',
     'fix':     '    '},
    {'title':   'No trailing whitespace on a line',
     'applies': ['*.c', '*.cpp', '*.h', '*.py', '*.sh'],
     'regex':   ' \n',
     'fix':     '\n'},
    {'title':   'No more than three consecutive newlines',
     'applies': ['*.c', '*.cpp', '*.h', '*.py', '*.sh'],
     'regex':   '\n\n\n\n',
     'fix':     '\n\n\n'},
    {'title':   'Do not end a line with a semicolon',
     'applies': ['*.py'],
     'regex':   ';\n',
     'fix':     '\n'},
    {'title':   'Do not end a line with two semicolons',
     'applies': ['*.c', '*.cpp', '*.h'],
     'regex':   ';;\n',
     'fix':     ';\n'},
]

SOURCE_FILES = list(set(itertools.chain(*[r['applies'] for r in STYLE_RULES])))

class BasicStyleRules(object):
    def __init__(self, repository):
        self.repository = repository
        self.rules = STYLE_RULES
        for rule in self:
            rule['regex_compiled'] = re.compile(rule['regex'])
            rule['filter'] = FileFilter()
            rule['filter'].append_include(rule['applies'],
                                          base_path=str(self.repository))

    def __iter__(self):
        return (rule for rule in self.rules)

    def rules_that_apply(self, file_path):
        return (rule for rule in self.rules if
                rule['filter'].evaluate(file_path))

    def rules_that_dont_apply(self, file_path):
        return (rule for rule in self.rules if not
                rule['filter'].evaluate(file_path))


###############################################################################
# gather file info
###############################################################################


def find_failures_for_rule(file_info, rule):
    matches = [match for match in
               rule['regex_compiled'].finditer(file_info['contents']) if
               match is not None]
    lines = [find_line_of_match(file_info['contents'], match) for match in
             matches]
    if len(lines) > 0:
        yield {'filename': file_info['filename'],
               'contents': file_info['contents'],
               'title':    rule['title'],
               'lines':    lines,
               'rule':     rule}


def find_failures(file_info):
    return list(itertools.chain(*[find_failures_for_rule(file_info, rule)
                                  for rule in file_info['rules']]))


def gather_file_info(filename):
    file_info = {}
    file_info['filename'] = filename
    file_info['contents'] = read_file(filename)
    file_info['rules'] = [r for r in STYLE_RULES if
                          r['applies_compiled'].match(filename)]
    file_info['rules_not_covering'] = [r for r in STYLE_RULES if not
                                       r['applies_compiled'].match(filename)]
    file_info['failures'] = find_failures(file_info)
    return file_info


###############################################################################
# report execution
###############################################################################


def report_filenames(file_infos):
    if len(file_infos) == 0:
        return
    R.add('\t')
    R.add('\n\t'.join([file_info['filename'] for file_info in file_infos]))
    R.add('\n')


def report_summary(file_infos, full_file_list):
    R.add("%4d files tracked according to '%s'\n" %
          (len(full_file_list), GIT_LS_CMD))
    R.add("%4d files examined according to STYLE_RULES and ALWAYS_IGNORE "
          "settings\n" % len(file_infos))


def file_fails_rule(file_info, rule):
    return len([failure for failure in file_info['failures'] if
                failure['rule'] is rule]) > 0


def report_rule(rule, file_infos):
    covered = [file_info for file_info in file_infos if
               rule in file_info['rules']]
    not_covered = [file_info for file_info in file_infos if
                   rule in file_info['rules_not_covering']]

    passed = [file_info for file_info in file_infos if not
              file_fails_rule(file_info, rule)]
    failed = [file_info for file_info in file_infos if
              file_fails_rule(file_info, rule)]

    R.add('Rule title: "%s"\n' % rule['title'])
    R.add('File extensions covered by rule:    %s\n' % rule['applies'])
    R.add("Files covered by rule:             %4d\n" % len(covered))
    R.add("Files not covered by rule:         %4d\n" % len(not_covered))
    R.add("Files passed:                      %4d\n" % len(passed))
    R.add("Files failed:                      %4d\n" % len(failed))
    report_filenames(failed)


def print_report(file_infos, full_file_list):
    R.separator()
    report_summary(file_infos, full_file_list)
    for rule in STYLE_RULES:
        R.separator()
        report_rule(rule, file_infos)
    R.separator()
    R.flush()


def exec_report(base_directory):
    original_cwd = os.getcwd()
    os.chdir(base_directory)
    full_file_list = git_ls()
    file_infos = [gather_file_info(filename) for filename in
                  get_filenames_to_examine(full_file_list)]
    print_report(file_infos, full_file_list)
    os.chdir(original_cwd)


###############################################################################
# check execution
###############################################################################


def get_all_failures(file_infos):
    return list(itertools.chain(*[file_info['failures'] for file_info in
                file_infos]))


def report_failure(failure):
    R.add("An issue was found with ")
    R.add_red("%s\n" % failure['filename'])
    R.add('Rule: "%s"\n\n' % failure['title'])
    for line in failure['lines']:
        R.add('line %d:\n' % line['number'])
        R.add("%s" % line['contents'])
        R.add(' ' * (line['character'] - 1))
        R.add_red("^\n")


def print_check_report(file_infos, full_file_list, failures):
    R.separator()
    report_summary(file_infos, full_file_list)

    for failure in failures:
        R.separator()
        report_failure(failure)

    R.separator()
    if len(failures) == 0:
        R.add_green()("No style issues found!\n")
    else:
        R.add_red("These issues can be fixed automatically by running:\n")
        R.add("$ contrib/devtools/basic_style.py fix <base_directory>\n")
    R.separator()
    R.flush()


def exec_check(base_directory):
    original_cwd = os.getcwd()
    os.chdir(base_directory)
    full_file_list = git_ls()
    file_infos = [gather_file_info(filename) for filename in
                  get_filenames_to_examine(full_file_list)]
    failures = get_all_failures(file_infos)
    print_check_report(file_infos, full_file_list, failures)
    os.chdir(original_cwd)
    if len(failures) > 0:
        sys.exit("*** Style issues found!")


###############################################################################
# fix execution
###############################################################################


def fix_contents(contents, regex, fix):
    # Multiple instances of a particular issue could be present. For example,
    # multiple spaces at the end of a line. So, we repeat the
    # search-and-replace until search matches are exhausted.
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


def fix_loop():
    full_file_list = git_ls()
    # Multiple types of issues could be overlapping. For example, a tabstop at
    # the end of a line so the fix then creates whitespace at the end. We
    # repeat fix-up cycles until everything is cleared.
    while True:
        file_infos = [gather_file_info(filename) for filename in
                      get_filenames_to_examine(full_file_list)]
        failures = get_all_failures(file_infos)
        if len(failures) == 0:
            break
        fix_failures(failures)


def exec_fix(base_directory):
    original_cwd = os.getcwd()
    os.chdir(base_directory)
    fix_loop()
    os.chdir(original_cwd)


###############################################################################
# file info
###############################################################################

class BasicStyleFileInfo(FileInfo):
    """
    Obtains and represents the information regarding a single file obtained
    from clang-format.
    """
    def __init__(self, repository, file_path, rules):
        super().__init__(repository, file_path)
        self['rules_that_apply'] = list(rules.rules_that_apply(file_path))
        self['rules_that_dont_apply'] = (
            list(rules.rules_that_dont_apply(file_path)))

    def _find_line_of_match(self, match):
        contents_before_match = self['content'][:match.start()]
        contents_after_match = self['content'][match.end() - 1:]
        line_start_char = contents_before_match.rfind('\n') + 1
        line_end_char = match.end() + contents_after_match.find('\n')
        return {'context':   self['content'][line_start_char:line_end_char],
                'number':    contents_before_match.count('\n') + 1,
                'character': match.start() - line_start_char + 1}

    def _find_failures(self):
        for rule in self['rules_that_apply']:
            matches = [match for match in
                       rule['regex_compiled'].finditer(self['content']) if
                       match is not None]
            lines = [self._find_line_of_match(match) for match in matches]
            for line in lines:
                yield {'file_path':  self['file_path'],
                       'content':    self['content'],
                       'rule_title': rule['title'],
                       'line':       line}

    def compute(self):
        # TODO:
        self['fixed_content'] = self['content']
        self.set_write_content(self['fixed_content'])

        # diff info:
        self.update(StyleDiff(self['content'], self['fixed_content']))

        # failures info:
        self['failures'] = list(self._find_failures())


###############################################################################
# cmd base class
###############################################################################

class BasicStyleCmd(FileContentCmd):
    """
    Common base class for the commands in this script.
    """
    def __init__(self, repository, jobs, target_fnmatches, json):
        super().__init__(repository, jobs, SOURCE_FILES, REPO_INFO['subtrees'],
                         target_fnmatches, json)
        self.rules = BasicStyleRules(repository)

    def _file_info_list(self):
        return [BasicStyleFileInfo(self.repository, f, self.rules) for f in
                self.files_targeted]

###############################################################################
# report cmd
###############################################################################

class ReportCmd(BasicStyleCmd):
    """
    'report' subcommand class.
    """
    def _analysis(self):
        a = super()._analysis()
        return a

    def _human_print(self):
        super()._human_print()

    def _json_print(self):
        super()._json_print()


def add_report_cmd(subparsers):
    def exec_report_cmd(options):
        ReportCmd(options.repository, options.jobs,
                  options.target_fnmatches, options.json).exec()

    report_help = ("Valiates that the selected targets do not have basic style "
                  "issues, give a per-file report and returns a non-zero "
                  "shell status if there are any basic style issues "
                  "discovered.")
    parser = subparsers.add_parser('report', help=report_help)
    parser.set_defaults(func=exec_report_cmd)
    add_jobs_arg(parser)
    add_json_arg(parser)
    add_git_tracked_targets_arg(parser)

###############################################################################
# check cmd
###############################################################################

class CheckCmd(BasicStyleCmd):
    """
    'check' subcommand class.
    """

    def _analysis(self):
        a = super()._analysis()
        return a

    def _human_print(self):
        super()._human_print()

    def _json_print(self):
        super()._json_print()

    def _shell_exit(self):
        return (0 if len(self.results) == 0 else
                "*** code formatting issue found")

def add_check_cmd(subparsers):
    def exec_check_cmd(options):
        CheckCmd(options.repository, options.jobs,
                 options.target_fnmatches, options.json).exec()

    check_help = ("Valiates that the selected targets do not have basic style "
                  "issues, give a per-file report and returns a non-zero "
                  "shell status if there are any basic style issues "
                  "discovered.")
    parser = subparsers.add_parser('check', help=check_help)
    parser.set_defaults(func=exec_check_cmd)
    add_jobs_arg(parser)
    add_json_arg(parser)
    add_git_tracked_targets_arg(parser)

###############################################################################
# fix cmd
###############################################################################

class FixCmd(BasicStyleCmd):
    """
    'fix' subcommand class.
    """
    def __init__(self, repository, jobs, target_fnmatches):
        super().__init__(repository, jobs, target_fnmatches, False)

    def _analysis(self):
        return None

    def _human_print(self):
        pass

    def _json_print(self):
        pass

    def _write_files(self):
        self.file_infos.write_all()


def add_fix_cmd(subparsers):
    def exec_fix_cmd(options):
        FixCmd(options.repository, options.jobs,
               options.target_fnmatches).exec()

    fix_help = ("Applies basic style fixes to the target files.")
    parser = subparsers.add_parser('fix', help=fix_help)
    parser.set_defaults(func=exec_fix_cmd)
    add_jobs_arg(parser)
    add_git_tracked_targets_arg(parser)


###############################################################################
# UI
###############################################################################


if __name__ == "__main__":
    description = ("A utility for checking some basic style regexes against "
                   "the contents of source files in the repository. It "
                   "produces reports of style metrics and also can fix issues"
                   "with simple search-and-replace logic.")
    parser = argparse.ArgumentParser(description=description)
    subparsers = parser.add_subparsers()
    add_report_cmd(subparsers)
    add_check_cmd(subparsers)
    add_fix_cmd(subparsers)
    options = parser.parse_args()
    options.func(options)

