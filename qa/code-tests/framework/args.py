#!/usr/bin/env python3
# Copyright (c) 2017 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.


def add_jobs_arg(parser):
    j_help = "parallel jobs for computations (default=4)"
    parser.add_argument("-j", "--jobs", type=int, default=4, help=j_help)


def add_force_arg(parser):
    f_help = ("force proceeding with if clang-format doesn't support all "
              "parameters in the style file (default=False)")
    parser.add_argument("-f", "--force", action='store_true', help=f_help)


def add_json_arg(parser):
    j_help = "print output in json format (default=False)"
    parser.add_argument("--json", action='store_true', help=j_help)
