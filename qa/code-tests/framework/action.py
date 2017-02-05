#!/usr/bin/env python3
# Copyright (c) 2017 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import os
import argparse
import subprocess
from framework.path_arg import PathArg, GitPathArg


class ReadableFileAction(argparse.Action):
    """
    Validate that 'values' is a string that represents a path that points to a
    single readable file.
    """
    def __call__(self, parser, namespace, values, option_string=None):
        if not isinstance(values, str):
            os.exit("*** %s is not a string" % values)
        self.path = PathArg(values)
        self.path.assert_exists()
        self.path.assert_is_file()
        self.path.assert_mode(os.R_OK)


class ExecutableBinaryAction(argparse.Action):
    """
    Validate that 'values' is a string that represents a path that points to
    an executable.
    """
    def __call__(self, parser, namespace, values, option_string=None):
        if not isinstance(values, str):
            os.exit("*** %s is not a string" % values)
        self.path = PathArg(values)
        self.path.assert_exists()
        self.path.assert_is_file()
        self.path.assert_mode(os.R_OK | os.X_OK)


class TargetsAction(argparse.Action):
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
        targets = [GitPathArg(value) for value in values]
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
