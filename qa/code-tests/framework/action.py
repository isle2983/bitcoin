#!/usr/bin/env python3
# Copyright (c) 2017 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import os
import sys
import argparse
from framework.path import Path


class ReadableFileAction(argparse.Action):
    """
    Validate that 'values' is a string that represents a path that points to a
    single readable file.
    """
    def __call__(self, parser, namespace, values, option_string=None):
        if not isinstance(values, str):
            sys.exit("*** %s is not a string" % values)
        self.path = Path(values)
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
            sys.exit("*** %s is not a string" % values)
        self.path = Path(values)
        self.path.assert_exists()
        self.path.assert_is_file()
        self.path.assert_mode(os.R_OK | os.X_OK)
