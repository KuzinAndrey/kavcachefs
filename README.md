# kavcachefs - read-only cache file system based on FUSE (libfuse)

Provide simple caching layer for remote filesystems mounted by network connection,
for example NFS, Samba CIFS, sshfs and other. This make slow remote file content
access much faster for local usage.

## Description

After start kavcachefs read remote file structure into memory and emulate its contents
at mount point. All file read operations start background download thread for save
not cached files content in local directory. After download complete, all read
operation going from local copy. This useful for store infrequently modified files
locally for faster access, for example video, music, software repository packages
and other static stuff.

It has different eviction modes for delete cached files on local file system,
if it has no more free space for download any files:
- **no** - don't delete any file, all read operation for not cached files will going from remote directory if no more free space (also for file bigger than local filesystem total space)
- **random** - delete random file to get more free space for downloading other file
- **atime** - delete files that were read long time ago by last read access time

## Usage

```
$ ./kavcachefs -h
Read-only cache file system based on FUSE. Author: Kuzin Andrey <kuzinandrey@yandex.ru>

Usage: ./kavcachefs [options] <mountpoint>

Options:
    --remote=<s>       mount point of remote file system (nfs, cifs, sshfs)
    --local=<s>        local mount point for store cached files
    --eviction=<s>     remove cached files for get free space (no, random, atime)

Description:
    ./kavcachefs this is read-only cache file system based on FUSE.
    At start it read remote file system directory and emulate its content in <mountpoint>.
    Any read operation start background copy process from remote to local dir for not cached files.
    For already cached files all read operation make from local directory.
    Eviction rules to clean space if no any free space for download:
    no - store permanent, random - delete random file, atime - find old file by access time

Signals:
    USR1 - reload content of remote directory
```
