#!/usr/bin/env python3
# Copyright (c) 2017 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import os
import sys
import subprocess
import argparse
from framework.path import Path

class GitPath(Path):
    """
    A Path that has some additional functions for awareness of the git
    repository that holds the path.
    """
    def _in_git_repository(self):
        cmd = 'git -C %s status' % self.directory()
        dn = open(os.devnull, 'w')
        return subprocess.call(cmd.split(' '), stderr=dn, stdout=dn) == 0;

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


class GitTrackedTargetsAction(argparse.Action):
    """
    Validate that 'values' is a list of strings that all represent files or
    directories under a git repository path.
    """
    def _check_values(self, values):
        if not isinstance(values, list):
            os.exit("*** %s is not a list" % values)
        types = [type(value) for value in values]
        if len(set(types)) != 1:
            os.exit("*** %s has multiple object types" % values)
        if not isinstance(values[0], str):
            os.exit("*** %s does not contain strings" % values)

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
        return repositories[0]

    def __call__(self, parser, namespace, values, option_string=None):
        self._check_values(values)
        targets = self._get_targets(values)
        namespace.repository = self._get_common_repository(targets)
        target_files = [os.path.join(namespace.repository, str(t)) for t in
                        targets if t.is_file()]
        target_directories = [os.path.join(namespace.repository, str(t)) for t
                              in targets if t.is_directory()]
        namespace.target_fnmatches = (target_files +
            [os.path.join(d, '*') for d in target_directories])
