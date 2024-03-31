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
#REMOTE_DIR="/usr/bin"
#LOCAL_DIR="/mnt/mytmpfs/123"
LOCAL_DIR="/dev/shm/kavcache"
MOUNT_POINT="./123a"

VO="--leak-check=full"
VO=$VO" --show-leak-kinds=all"
VO=$VO" --track-origins=yes"
#VO=$VO" --error-limit=no"
#VG="valgrind $VO"
VG=""

EVICTION="random"
#EVICTION="atime"

[ ! -d $LOCAL_DIR ] && mkdir $LOCAL_DIR
[ -x ./kavcachefs -a -r $REMOTE_DIR -a -w $LOCAL_DIR ] && \
	$VG ./kavcachefs --remote=$REMOTE_DIR --local=$LOCAL_DIR --eviction=$EVICTION -f $MOUNT_POINT
