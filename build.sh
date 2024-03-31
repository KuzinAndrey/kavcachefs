#!/bin/bash
#
#  sudo apt install fuse3 libfuse3-3 libfuse3-dev
#

[ -x ./kavcachefs ] && rm ./kavcachefs
MODE="-ggdb"
[ ! -z "$1" ] && [ "$1" == "prod" ] && MODE="-s -DPRODUCTION=1"

gcc -Wall $MODE -pedantic kavcachefs.c `pkg-config fuse3 --cflags --libs` -o kavcachefs
