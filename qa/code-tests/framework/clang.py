#!/usr/bin/env python3
# Copyright (c) 2017 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import re
import os
import subprocess
import argparse
from framework.path_arg import PathArg
from framework.action import ExecutableBinaryAction

###############################################################################
# The clang binaries of interest to this framework
###############################################################################

CLANG_BINARIES = ['clang-format', 'scan-build', 'scan-view']

###############################################################################
# Find the version of a particular binary
###############################################################################

# the method of finding the version of a particluar binary:
ASK_FOR_VERSION = ['clang-format']
VERSION_FROM_PATH= ['scan-build', 'scan-view']

assert set(ASK_FOR_VERSION + VERSION_FROM_PATH) == set(CLANG_BINARIES)

# Find the version in the output of '--version'.
VERSION_ASK_REGEX = re.compile("version (?P<version>[0-9]\.[0-9](\.[0-9])?)")

# Find the version in the name of a containing subdirectory.
VERSION_PATH_REGEX = re.compile("(?P<version>[0-9]\.[0-9](\.[0-9])?)")

class ClangVersion(object):
    def __init__(self, binary_path):
        p = PathArg(binary_path)
        if p.filename() in ASK_FOR_VERSION:
            self.version = self._version_from_asking(binary_path)
        else:
            self.version = self._version_from_path(binary_path)

    def __str__(self):
        return self.version

    def _version_from_asking(self, binary_path):
        p = subprocess.Popen([str(binary_path), '--version'],
                              stdout=subprocess.PIPE)
        match = VERSION_ASK_REGEX.search(p.stdout.read().decode('utf-8'))
        if not match:
            return "0.0.0"
        return match.group('version')

    def _version_from_path(self, binary_path):
        match = VERSION_PATH_REGEX.search(str(binary_path))
        if not match:
            return "0.0.0"
        return match.group('version')

###############################################################################
# find usable clang binaries
###############################################################################

class ClangFind(object):
    """
    Assist finding clang tool binaries via either a parameter pointing to
    a directory or by examinining the environment for installed binaries.
    """
    def __init__(self, path_arg_str=None):
        if path_arg_str:
            # Infer the directory from the provided path.
            search_directories = [self._parameter_directory(path_arg_str)]
        else:
            # Use the directories with installed clang binaries
            # in the PATH environment variable.
            search_directories = list(set(self._installed_directories()))
        self.binaries = self._find_binaries(search_directories)

    def _parameter_directory(self, path_arg_str):
        print(path_arg_str)
        p = PathArg(path_arg_str)
        p.assert_exists()
        # Tarball-download versions of clang put binaries in a bin/
        # subdirectory. For convenience, tolerate a parameter of either:
        # <unpacked_tarball>, <unpacked tarball>/bin or
        # <unpacked_tarball>/bin/<specific_binary>
        if p.is_file():
            return p.directory()
        bin_subdir = os.path.join(str(p), "bin/")
        if os.path.exists(bin_subdir):
            print("subdir %s\n" % bin_subdir)
            return bin_subdir
        return str(p)

    def _installed_directories(self):
        for path in os.environ["PATH"].split(os.pathsep):
            for e in os.listdir(path):
                b = PathArg(os.path.join(path, e))
                if b.is_file() and b.filename() in CLANG_BINARIES:
                    yield b.directory()

    def _find_binaries(self, search_directories):
        binaries = {}
        for directory in search_directories:
            for binary in CLANG_BINARIES:
                path = PathArg(os.path.join(directory, binary))
                if not path.exists():
                    continue
                path.assert_is_file()
                path.assert_mode(os.R_OK | os.X_OK)
                if path.filename() not in binaries:
                    binaries[path.filename()] = []
                version = str(ClangVersion(str(path)))
                binaries[path.filename()].append({'path': str(path),
                                                  'version': version})
        return binaries

    def _highest_version(self, versions):
        return max(versions, key=lambda b: b['version'])

    def best_binaries(self):
        return {name: self._highest_version(versions) for name, versions in
                self.binaries.items()}

    def best(self, bin_name):
        return self.best_binaries()[bin_name]


###############################################################################
# action
###############################################################################

class ClangDirectoryAction(argparse.Action):
    """
    Validate that 'values' is a path that points to a directory that has
    clang executables in it. The set of clang binaries contained is returned
    along with their detected version. Tolerates either a directory, a
    directory with a 'bin/' subdirectory or a path to an executable file.
    """
    def __call__(self, parser, namespace, values, option_string=None):
        if not isinstance(values, str):
            os.exit("*** %s is not a string" % values)
        namespace.clang_executables = ClangFind(values).best_binaries()
