#!/bin/bash
cd ..
#./test.py -s ipv4-address -t result.txt
#cat result.txt
./waf --run libtorrentDriver 
rm tracker.db
cd src
