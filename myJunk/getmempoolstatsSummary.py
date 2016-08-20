#!/usr/bin/python

import json
import fileinput

inputStr = ""
for line in fileinput.input():
    inputStr = inputStr + line.rstrip()

getmempoolstats = json.loads(inputStr)

getmempoolstats['samples'] = None

print json.dumps(getmempoolstats)

