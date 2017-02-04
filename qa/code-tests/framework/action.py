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
    def __call__(self, parser, namespace, values, option_string=None):
        if not isinstance(values, list):
            os.exit("*** %s is not a list" % values)
        types = [type(value) for value in values]
        if len(set(types)) != 1:
            os.exit("*** %s has multiple object types" % values)
        if not isinstance(types[0], str):
            os.exit("*** %s does not contain strings" % values)
        self.targets = [GitPathArg(value) for value in values]
        for target in self.targets:
            target.assert_exists()
            target.assert_mode(os.R_OK)
        repositories = [str(target.repository_base()) for target in
                        self.targets]
        if len(set(repositories)) > 1:
            sys.exit("*** targets from multiple repositories %s" %
                     set(repositories))
        for target in self.targets:
            target.assert_under_directory(repositories[0])
