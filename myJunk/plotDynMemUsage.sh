#!/bin/sh
echo "getmempoolstats" | bitcoin-cli -stdin --datadir=/home/isle/mainnet-data/ | ./myJunk/getmempoolstatsToCsv.py | gnuplot -p -e "set datafile separator ','; plot '-' using 1:3 w l"
