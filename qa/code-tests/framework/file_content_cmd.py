#!/usr/bin/env python3
# Copyright (c) 2017 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import time
import json
import sys
from framework.report import Report
from framework.file_filter import FileFilter
from framework.file_info import FileInfos


class FileContentCmd(object):
    """
    Base class for commands that compute info on a set of files based on
    the content inside of the files. Provides a common way for indicating
    a subset of files that the operation is to apply to via lists of
    fnmatch expressions.
    """
    def __init__(self, repository, jobs, include_fnmatches, exclude_fnmatches,
                 target_fnmatches, json):
        self.repository = repository
        self.jobs = jobs
        self.json = json
        self.tracked_files = self._get_tracked_files(self.repository)
        self.files_in_scope = list(self._files_in_scope(self.repository,
                                                        self.tracked_files,
                                                        include_fnmatches,
                                                        exclude_fnmatches))
        self.files_targeted = list(self._files_targeted(self.repository,
                                                        self.files_in_scope,
                                                        include_fnmatches,
                                                        exclude_fnmatches,
                                                        target_fnmatches))
        self.report = Report()

    def _get_tracked_files(self, repository):
        return repository.tracked_files()

    def _scope_filter(self, repository, include_fnmatches, exclude_fnmatches):
        file_filter = FileFilter()
        file_filter.append_include(include_fnmatches,
                                   base_path=str(repository))
        file_filter.append_exclude(exclude_fnmatches,
                                   base_path=str(repository))
        return file_filter

    def _files_in_scope(self, repository, tracked_files, include_fnmatches,
                        exclude_fnmatches):
        file_filter = self._scope_filter(repository, include_fnmatches,
                                         exclude_fnmatches)
        return (f for f in tracked_files if file_filter.evaluate(f))

    def _target_filter(self, repository, include_fnmatches, exclude_fnmatches,
                       target_fnmatches):
        file_filter = self._scope_filter(repository, include_fnmatches,
                                         exclude_fnmatches)
        file_filter.append_include(target_fnmatches, base_path=repository)
        return file_filter

    def _files_targeted(self, repository, tracked_files, include_fnmatches,
                        exclude_fnmatches, target_fnmatches):
        file_filter = self._target_filter(repository, include_fnmatches,
                                          exclude_fnmatches, target_fnmatches)
        return (f for f in tracked_files if file_filter.evaluate(f))

    def _read_file_infos(self):
        self.file_infos.read_all()

    def _compute_file_infos(self):
        self.file_infos.compute_all()

    def _read_and_compute_file_infos(self):
        start_time = time.time()
        self.file_infos = FileInfos(self.jobs, self._file_info_list())
        self._read_file_infos()
        self._compute_file_infos()
        self.elapsed_time = time.time() - start_time

    def _write_files(self):
        pass

    def _analysis(self):
        a = {}
        a['tracked_files'] = len(self.tracked_files)
        a['files_in_scope'] = len(self.files_in_scope)
        a['files_targeted'] = len(self.files_targeted)
        return a

    def _human_print(self):
        r = self.report
        a = self.results
        r.separator()
        r.add("%4d files tracked in repo\n" % a['tracked_files'])
        r.add("%4d files in scope according to script settings\n" %
              a['files_in_scope'])
        r.add("%4d files examined according to listed targets\n" %
              a['files_targeted'])
        r.separator()

    def _json_print(self):
        print(json.dumps(self.results))

    def _shell_exit(self):
        return 0

    def exec_analysis(self):
        self._read_and_compute_file_infos()
        self.results = self._analysis()
        self._json_print() if self.json else self._human_print()
        sys.exit(self._shell_exit())

    def exec_write(self):
        self._read_and_compute_file_infos()
        self._write_files()
        sys.exit(self._shell_exit())
