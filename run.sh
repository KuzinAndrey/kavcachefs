#!/bin/sh

#
#  sudo apt install fuse3 libfuse3-3 libfuse3-dev
#

# sudo mkdir /mnt/mytmpfs
# sudo mount -t tmpfs -o size=10M tmpfs /mnt/mytmpfs
#

if ! lsmod | grep fuse 1> /dev/null 2> /dev/null ; then
	sudo modprobe fuse && echo "Activate kernel module fuse..." || exit 1
fi

REMOTE_DIR="/usr/include"
LOCAL_DIR="/dev/shm/kavcache"
MOUNT_POINT="./123a"

EVICTION="random"
#EVICTION="atime"

[ ! -d $LOCAL_DIR ] && mkdir $LOCAL_DIR
[ -x ./kavcachefs -a -r $REMOTE_DIR -a -w $LOCAL_DIR ] && \
	./kavcachefs --remote=$REMOTE_DIR --local=$LOCAL_DIR --eviction=$EVICTION $MOUNT_POINT
