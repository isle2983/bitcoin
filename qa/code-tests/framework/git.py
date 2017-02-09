#!/usr/bin/env python3
# Copyright (c) 2017 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import os
import sys
import subprocess
import argparse
from framework.path import Path


###############################################################################
# path in repository
###############################################################################

class GitPath(Path):
    """
    A Path that has some additional functions for awareness of the git
    repository that holds the path.
    """
    def _in_git_repository(self):
        cmd = 'git -C %s status' % self.directory()
        dn = open(os.devnull, 'w')
        return subprocess.call(cmd.split(' '), stderr=dn, stdout=dn) == 0

    def assert_in_git_repository(self):
        if not self._in_git_repository():
            sys.exit("*** %s is not inside a git repository" % self)

    def _is_repository_base(self):
        self.assert_is_directory()
        return Path(os.path.join(self.path, '.git/')).exists()

    def repository_base(self):
        directory = GitPath(self.directory())
        if directory._is_repository_base():
            return directory

        def recurse_repo_base_dir(git_path_arg):
            git_path_arg.assert_in_git_repository()
            d = GitPath(git_path_arg.containing_directory())
            if str(d) is '/':
                sys.exit("*** did not find underlying repo?")
            if d._is_repository_base():
                return d
            return recurse_repo_base_dir(d)

        return recurse_repo_base_dir(self)


###############################################################################
# repository
###############################################################################

class GitRepository(object):
    """
    Represents and queries information from a git repository clone.
    """
    def __init__(self, repository_base):
        self.repository_base = repository_base
        git_path = GitPath(repository_base)
        git_path.assert_exists()
        git_path.assert_mode(os.R_OK)
        git_path.assert_in_git_repository()
        if str(self.repository_base) != str(git_path.repository_base()):
            sys.exit("*** %s is not the base of its repository" %
                     self.repository_base)

    def __str__(self):
        return self.repository_base

    def tracked_files(self):
        out = subprocess.check_output(['git', 'ls-files'])
        return [os.path.join(self.repository_base, f) for f in
                out.decode("utf-8").split('\n') if f != '']


###############################################################################
# getting a list of target fnmatches in a repo from args
###############################################################################

class GitTrackedTargetsAction(argparse.Action):
    """
    Validate that 'values' is a list of strings that all represent files or
    directories under a git repository path.
    """
    def _check_values(self, values):
        if not isinstance(values, list):
            sys.exit("*** %s is not a list" % values)
        types = [type(value) for value in values]
        if len(set(types)) != 1:
            sys.exit("*** %s has multiple object types" % values)
        if not isinstance(values[0], str):
            sys.exit("*** %s does not contain strings" % values)

    def _get_targets(self, values):
        targets = [GitPath(value) for value in values]
        for target in targets:
            target.assert_exists()
            target.assert_mode(os.R_OK)
        return targets

    def _get_common_repository(self, targets):
        repositories = [str(target.repository_base()) for target in targets]
        if len(set(repositories)) > 1:
            sys.exit("*** targets from multiple repositories %s" %
                     set(repositories))
        for target in targets:
            target.assert_under_directory(repositories[0])
        return GitRepository(repositories[0])

    def __call__(self, parser, namespace, values, option_string=None):
        self._check_values(values)
        targets = self._get_targets(values)
        namespace.repository = self._get_common_repository(targets)

        target_files = [os.path.join(str(namespace.repository), str(t)) for t
                        in targets if t.is_file()]
        target_directories = [os.path.join(str(namespace.repository), str(t))
                              for t in targets if t.is_directory()]
        namespace.target_fnmatches = (target_files +
                                      [os.path.join(d, '*') for d in
                                       target_directories])


def add_git_tracked_targets_arg(parser):
    t_help = ("A list of files and/or directories that select the subset of "
              "files for this action. If a directory is given as a target, "
              "all files contained in it and its subdirectories are "
              "recursively selected. All targets must be tracked in the same "
              "git repository clone. (default=The current directory)")
    parser.add_argument("target", type=str, action=GitTrackedTargetsAction,
                        nargs='*', default=['.'], help=t_help)
