#!/usr/bin/env python3
# Copyright (c) 2017 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import re
import os
import sys
import subprocess
import argparse
from framework.path import Path
from framework.action import ExecutableBinaryAction
from framework.action import ReadableFileAction
from framework.io import read_file, write_file

###############################################################################
# The clang binaries of interest to this framework
###############################################################################

CLANG_BINARIES = ['clang-format', 'scan-build', 'scan-view']

###############################################################################
# Find the version of a particular binary
###############################################################################

# the method of finding the version of a particluar binary:
ASK_FOR_VERSION = ['clang-format']
VERSION_FROM_PATH = ['scan-build', 'scan-view']

assert set(ASK_FOR_VERSION + VERSION_FROM_PATH) == set(CLANG_BINARIES)

# Find the version in the output of '--version'.
VERSION_ASK_REGEX = re.compile("version (?P<version>[0-9]\.[0-9](\.[0-9])?)")

# Find the version in the name of a containing subdirectory.
VERSION_PATH_REGEX = re.compile("(?P<version>[0-9]\.[0-9](\.[0-9])?)")


class ClangVersion(object):
    """
    Obtains and represents the version of a particular clang binary.
    """
    def __init__(self, binary_path):
        p = Path(binary_path)
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
        p = Path(path_arg_str)
        p.assert_exists()
        # Tarball-download versions of clang put binaries in a bin/
        # subdirectory. For convenience, tolerate a parameter of either:
        # <unpacked_tarball>, <unpacked tarball>/bin or
        # <unpacked_tarball>/bin/<specific_binary>
        if p.is_file():
            return p.directory()
        bin_subdir = os.path.join(str(p), "bin/")
        if os.path.exists(bin_subdir):
            return bin_subdir
        return str(p)

    def _installed_directories(self):
        for path in os.environ["PATH"].split(os.pathsep):
            for e in os.listdir(path):
                b = Path(os.path.join(path, e))
                if b.is_file() and b.filename() in CLANG_BINARIES:
                    yield b.directory()

    def _find_binaries(self, search_directories):
        binaries = {}
        for directory in search_directories:
            for binary in CLANG_BINARIES:
                path = Path(os.path.join(directory, binary))
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
# argparse utilities
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
            sys.exit("*** %s is not a string" % values)
        namespace.clang_executables = ClangFind(values).best_binaries()


###############################################################################
# style
###############################################################################

class ClangFormatStyle(object):
    """
    Reads and parses a .clang-format style file to represent it. The style can
    have keys removed and it can be translated into a '--style' argument for
    invoking clang-format.
    """
    def __init__(self, file_path):
        p = Path(file_path)
        p.assert_exists()
        p.assert_is_file()
        p.assert_mode(os.R_OK)
        self.file_path = file_path
        self.raw_contents = read_file(file_path)
        self.parameters = self._parse_parameters()
        self.rejected_parameters = {}

    def __str__(self):
        return self.file_path

    def _parse_parameters(self):
        # Python does not have a built-in yaml parser, so here is a
        # hand-written one that *seems* to minimally work for this purpose.
        many_spaces = re.compile(': +')
        spaces_removed = many_spaces.sub(':', self.raw_contents)
        # split into a list of lines
        lines = [l for l in spaces_removed.split('\n') if l != '']
        # split by the colon separator
        split = [l.split(':') for l in lines]
        # present as a dictionary
        return {item[0]: ''.join(item[1:]) for item in split}

    def reject_parameter(self, key):
        if key not in self.rejected_parameters:
            self.rejected_parameters[key] = self.parameters.pop(key)

    def style_arg(self):
        return '-style={%s}' % ', '.join(["%s: %s" % (k, v) for k, v in
                                          self.parameters.items()])


###############################################################################
# clang format class
###############################################################################

class ClangFormat(object):
    """
    Facility to read in the formatted content of a file using a particular
    clang-format binary and style file.
    """
    def __init__(self, binary, style_path):
        self.binary_path = binary['path']
        self.binary_version = binary['version']
        self.style_path = style_path
        self.style = ClangFormatStyle(self.style_path)
        self.UNKNOWN_KEY_REGEX = re.compile("unknown key '(?P<key_name>\w+)'")

    def _parse_unknown_key(self, err):
        if len(err) == 0:
            return 0, None
        match = self.UNKNOWN_KEY_REGEX.search(err)
        if not match:
            return len(err), None
        return len(err), match.group('key_name')

    def _try_format_file(self, file_path):
        cmd = [self.binary_path, self.style.style_arg(), file_path]
        return subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)

    def read_formatted_file(self, file_path):
        while True:
            p = self._try_format_file(file_path)
            out = p.stdout.read().decode('utf-8')
            err = p.stderr.read().decode('utf-8')
            p.communicate()
            if p.returncode != 0:
                sys.exit("*** clang-format could not execute")
            # Older versions of clang don't support some style parameter keys,
            # so we work around by redacting any key that gets rejected until
            # we find a subset of parameters that can apply the format without
            # producing any stderr output.
            err_len, unknown_key = self._parse_unknown_key(err)
            if not unknown_key and err_len > 0:
                sys.exit("*** clang-format produced unknown output to stderr")
            if unknown_key:
                self.style.reject_parameter(unknown_key)
                continue
            return out

    def rejected_parameters(self):
        return self.style.rejected_parameters


###############################################################################
# getting a clang format class from args
###############################################################################


def add_clang_format_args(parser):
    b_help = ("path to the clang directory or binary to be used "
              "(default=The required clang binary installed in PATH with the "
              "highest version number)")
    sf_help = ("path to the clang style file to be used (default=The "
               "src/.clang_format file of the repository which holds the "
               "targets)")
    parser.add_argument("-b", "--bin-path", type=str,
                        action=ClangDirectoryAction, help=b_help)
    parser.add_argument("-s", "--style-file", type=str,
                        action=ReadableFileAction, help=sf_help)


def clang_format_from_options(options, style_file_default):
    binary = (options.clang_executables['clang-format'] if
              hasattr(options, 'clang_executables') else
              ClangFind().best('clang-format'))
    style_path = (options.style_file if options.style_file else
                  os.path.join(str(options.repository), style_file_default))
    return ClangFormat(binary, style_path)
