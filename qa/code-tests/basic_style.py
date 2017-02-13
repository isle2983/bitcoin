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


class BasicStyleRules(object):
    """
    Wrapping of the above rules to provide helpers.
    """
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

    def rule_with_title(self, title):
        return next((rule for rule in self.rules if rule['title'] == title),
                    None)


###############################################################################
# define which files the rules apply to
###############################################################################

REPO_INFO = {
    'subtrees': ['src/secp256k1/*',
                 'src/leveldb/*',
                 'src/univalue/*',
                 'src/crypto/ctaes/*'],
}

SOURCE_FILES = list(set(itertools.chain(*[r['applies'] for r in STYLE_RULES])))


###############################################################################
# file info
###############################################################################

class BasicStyleFileInfo(FileInfo):
    """
    Obtains and represents the information regarding a single file.
    """
    def __init__(self, repository, file_path, rules):
        super().__init__(repository, file_path)
        self.rules = rules
        self['rules_that_apply'] = list(self.rules.rules_that_apply(file_path))

    def _find_line_of_match(self, match):
        contents_before_match = self['content'][:match.start()]
        contents_after_match = self['content'][match.end() - 1:]
        line_start_char = contents_before_match.rfind('\n') + 1
        line_end_char = match.end() + contents_after_match.find('\n')
        return {'context':   self['content'][line_start_char:line_end_char],
                'number':    contents_before_match.count('\n') + 1,
                'character': match.start() - line_start_char + 1}

    def _find_issues(self, content):
        for rule in self['rules_that_apply']:
            matches = [match for match in
                       rule['regex_compiled'].finditer(content) if
                       match is not None]
            lines = [self._find_line_of_match(match) for match in matches]
            for line in lines:
                yield {'file_path':  self['file_path'],
                       'rule_title': rule['title'],
                       'line':       line}

    def _apply_fix(self, content, rule_title):
        # Multiple instances of a particular issue could be present. For
        # example, multiple spaces at the end of a line. So, we repeat the
        # search-and-replace until search matches are exhausted.
        fixed_content = content
        while True:
            rule = self.rules.rule_with_title(rule_title)
            fixed_content, subs = rule['regex_compiled'].subn(rule['fix'],
                                                              fixed_content)
            if subs == 0:
                break
        return fixed_content

    def _fix_content(self):
        fixed_content = self['content']
        issues = self['issues']
        # Multiple types of issues could be overlapping. For example, a tabstop
        # at the end of a line so the fix then creates whitespace at the end.
        # We repeat fix-up cycles until everything is cleared.
        while len(issues) > 0:
            fixed_content = self._apply_fix(fixed_content,
                                            issues[0]['rule_title'])
            issues = list(self._find_issues(fixed_content))
        return fixed_content

    def compute(self):
        self['issues'] = list(self._find_issues(self['content']))
        self['fixed_content'] = self._fix_content()
        self.set_write_content(self['fixed_content'])
        self.update(StyleDiff(self['content'], self['fixed_content']))
        self['matching'] = self['content'] == self['fixed_content']


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
        file_infos = self.file_infos
        a['jobs'] = self.jobs
        a['elapsed_time'] = self.elapsed_time
        a['lines_before'] = sum(f['lines_before'] for f in file_infos)
        a['lines_added'] = sum(f['lines_added'] for f in file_infos)
        a['lines_removed'] = sum(f['lines_removed'] for f in file_infos)
        a['lines_unchanged'] = sum(f['lines_unchanged'] for f in file_infos)
        a['lines_after'] = sum(f['lines_after'] for f in file_infos)
        score = StyleScore(a['lines_before'], a['lines_added'],
                           a['lines_removed'], a['lines_unchanged'],
                           a['lines_after'])
        a['style_score'] = float(score)
        a['matching'] = sum(1 for f in file_infos if f['matching'])
        a['not_matching'] = sum(1 for f in file_infos if not f['matching'])

        all_issues = list(itertools.chain.from_iterable(
            file_info['issues'] for file_info in file_infos))

        a['rule_evaluation'] = {}
        for rule in self.rules:
            examined = sum(1 for f in file_infos if
                           rule['filter'].evaluate(f['file_path']))
            occurrence_count = len([f for f in all_issues if
                                    f['rule_title'] == rule['title']])
            file_count = len(set([f['file_path'] for f in all_issues if
                                  f['rule_title'] == rule['title']]))
            a['rule_evaluation'][rule['title']] = (
                {'extensions': rule['applies'], 'examined': examined,
                 'files': file_count, 'occurrences': occurrence_count})
        return a

    def _human_print(self):
        super()._human_print()
        r = self.report
        a = self.results
        r.add("Parallel jobs for diffs:   %d\n" % a['jobs'])
        r.add("Elapsed time:              %.02fs\n" % a['elapsed_time'])
        r.separator()
        for title, evaluation in sorted(a['rule_evaluation'].items()):
            r.add('"%s":\n' % title)
            r.add('    Applies to:               %s\n' %
                  evaluation['extensions'])
            r.add('    Files examined:           %8d\n' %
                  evaluation['examined'])
            r.add('    Occurrences of issue:     %8d\n' %
                  evaluation['occurrences'])
            r.add('    Files with issue:         %8d\n\n' %
                  evaluation['files'])
        r.separator()
        r.add("Files scoring 100%%:        %8d\n" % a['matching'])
        r.add("Files scoring <100%%:       %8d\n" % a['not_matching'])
        r.separator()
        r.add("Overall scoring:\n\n")
        score = StyleScore(a['lines_before'], a['lines_added'],
                           a['lines_removed'], a['lines_unchanged'],
                           a['lines_after'])
        r.add(str(score))
        r.separator()
        r.flush()


def add_report_cmd(subparsers):
    def exec_report_cmd(options):
        ReportCmd(options.repository, options.jobs,
                  options.target_fnmatches, options.json).exec_analysis()

    report_help = ("Validates that the selected targets do not have basic "
                   "style issues, give a per-file report and returns a "
                   "non-zero shell status if there are any basic style issues "
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
        file_infos = self.file_infos
        a['issues'] = list(
            itertools.chain.from_iterable(f['issues'] for f in file_infos))
        return a

    def _human_print(self):
        super()._human_print()
        r = self.report
        a = self.results
        for issue in a['issues']:
            r.separator()
            r.add("An issue was found with ")
            r.add_red("%s\n" % issue['file_path'])
            r.add('Rule: "%s"\n\n' % issue['rule_title'])
            r.add('line %d:\n' % issue['line']['number'])
            r.add("%s" % issue['line']['context'])
            r.add(' ' * (issue['line']['character'] - 1))
            r.add_red("^\n")
        r.separator()
        if len(a['issues']) == 0:
            r.add_green("No style issues found!\n")
        else:
            r.add_red("These issues can be fixed automatically by running:\n")
            r.add("$ contrib/devtools/basic_style.py fix [target "
                  "[target ...]]\n")
        r.separator()
        r.flush()

    def _json_print(self):
        super()._json_print()

    def _shell_exit(self):
        return (0 if len(self.results['issues']) == 0 else
                "*** code formatting issue found")


def add_check_cmd(subparsers):
    def exec_check_cmd(options):
        CheckCmd(options.repository, options.jobs,
                 options.target_fnmatches, options.json).exec_analysis()

    check_help = ("Validates that the selected targets do not have basic style "
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

    def _write_files(self):
        self.file_infos.write_all()


def add_fix_cmd(subparsers):
    def exec_fix_cmd(options):
        FixCmd(options.repository, options.jobs,
               options.target_fnmatches).exec_write()

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
    if not hasattr(options, "func"):
        parser.print_help()
        sys.exit("*** missing argument")
    options.func(options)
