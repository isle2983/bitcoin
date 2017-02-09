#!/usr/bin/env python3
# Copyright (c) 2017 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.


def read_file(file_path):
    file = open(file_path, 'r')
    contents = file.read()
    file.close()
    return contents


def write_file(file_path, contents):
    file = open(file_path, 'w')
    file.write(contents)
    file.close()
