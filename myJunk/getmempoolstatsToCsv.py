#!/usr/bin/python

import json
import fileinput

inputStr = ""
for line in fileinput.input():
    inputStr = inputStr + line.rstrip()

getmempoolstats = json.loads(inputStr)
time_to = getmempoolstats['time_to']
time_from = getmempoolstats['time_from']
elapsed = time_to - time_from

for sample in getmempoolstats['samples']:
    print "%d,%d,%d,%d" % (int(sample[0]) - elapsed, sample[1], sample[2], sample[3])
