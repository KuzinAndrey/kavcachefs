/*
// kavcachefs: Remote file system read-only cache on local file system via FUSE
// Author: Kuzin Andrey <kuzinandrey@yandex.ru>
*/

#define FUSE_USE_VERSION 31

#include <fuse3/fuse.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <stddef.h>
#include <assert.h>
#include <limits.h> // PATH_MAX
#include <signal.h>

#include <libgen.h> // basename()
#include <dirent.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/vfs.h>

#include <sys/sendfile.h>

#include <pthread.h>

#ifndef PRODUCTION
#define TRACE fprintf(stderr,"TRACE %s:%d - %s()\n", __FILE__, __LINE__, __func__);
#define DEBUG(...) fprintf(stderr, __VA_ARGS__);
#else
#define TRACE
#define DEBUG(...)
#endif

enum eviction_enum {
		EVICTION_UNKNOWN = 0,
		EVICTION_NO,
		EVICTION_RANDOM,
		EVICTION_ATIME,
};
// Main program options
static struct options {
	char *remote;
	char *local;
	char *eviction_cli;
	enum eviction_enum eviction;
	int eviction_try;
	int show_help;
} options = {
	.remote = NULL,
	.local = NULL,
	.eviction_cli = NULL,
	.eviction = EVICTION_UNKNOWN,
	.eviction_try = 5,
};

const char *eviction_enum_string(enum eviction_enum v) {
	switch (v) {
	case EVICTION_UNKNOWN: return "UNKNOWN";
	case EVICTION_NO: return "NO";
	case EVICTION_RANDOM: return "RANDOM";
	case EVICTION_ATIME: return "ATIME";
	}
	return "unreachable place";
} // eviction_enum_string()

#define OPTION(t, p) { t, offsetof(struct options, p), 1 }
static const struct fuse_opt option_spec[] = {
	OPTION("--remote=%s", remote),
	OPTION("--local=%s", local),
	OPTION("--eviction=%s", eviction_cli),
	OPTION("--eviction_try=%d", eviction_try),
	OPTION("-h", show_help),
	OPTION("--help", show_help),
	FUSE_OPT_END
};

// File record for store remote directory structure as tree in memory
struct file_record_st {
	union {
		char *dir;
		char *name;
		char *symlink;
		struct file_record_st *subdir;
	} val;
	ino_t ino;
	off_t size;
	mode_t mode;
	time_t atime;
	time_t mtime;
	struct file_record_st *next;
	struct file_record_st *prev_cached; // list of cached files used for eviction
	struct file_record_st *next_cached;
	enum {
		FILE_REC_UNKNOWN = 0,
		FILE_REC_FILE,
		FILE_REC_SYMLINK,
		FILE_REC_PARENTDIR,
		FILE_REC_SUBDIR,
	} type;
	enum {
		FILE_NOT_IN_CACHE = 0,
		FILE_IN_DOWNLOADING,
		FILE_IN_CACHE,
	} cache;
};

struct remote_filesystem_st;

// Download from remote dir queue
struct file_download_st {
	char *name;
	struct remote_filesystem_st *filesystem;
	struct file_record_st *rec;
	struct file_download_st *prev;
	struct file_download_st *next;
};

// State of remote file system
struct remote_filesystem_st {
	struct file_record_st *root;
	ino_t next_inode; // inode counter
	size_t total_size;
	size_t total_dirs;
	size_t total_files;
	size_t total_symlinks;
	size_t downloaded_files;
	size_t downloaded_size;
	size_t cached_files;
	size_t cached_size;
	size_t evicted_files;
	size_t evicted_size;
	size_t block_size;

	pthread_rwlock_t rwlock;

	size_t download_need_space;
	struct file_record_st *cached_list;
	struct file_download_st *download_list;
	pthread_mutex_t download_mutex;
} *global_tree = NULL;
pthread_mutex_t global_tree_mutex = PTHREAD_MUTEX_INITIALIZER;
static size_t global_tree_block_size = 512; // unknown (set from remote fs - usual 4096)
static size_t global_localfs_size = 0;

static time_t global_start_time = 0;

// FUSE operation: init
static void *kavcachefs_init(struct fuse_conn_info *conn,
		struct fuse_config *cfg)
{
	(void) conn;
//	cfg->kernel_cache = 1; // enable kernel cache
	cfg->kernel_cache = 0; // disable kernel cache
	// cfg->use_ino = 1;
	// cfg->nullpath_ok = 1;

	// cfg->entry_timeout = 0;
	// cfg->attr_timeout = 0;
	// cfg->negative_timeout = 0;

	return NULL;
} // kavcachefs_init()

// Scan file tree for path
struct file_record_st *find_file_record_for_path(struct file_record_st *root, const char *path) {
	const char *p = path;
	size_t len = 0;

	struct file_record_st *d = root;
	if (strcmp(path, "/") == 0) return d;

	while (1) {
		if (*p == '/') p++;
		if (d->type != FILE_REC_PARENTDIR) return NULL;
		struct file_record_st *n = d->next;
		d = NULL;
		while (n) {
			if (n->type == FILE_REC_FILE) {
				// DEBUG("f %s %s\n",n->val.name, p);
				len = strlen(n->val.name);
				if (strncmp(n->val.name, p, len) == 0) {
					if (*(p + len) == '\0') {
						// DEBUG("found file %s = %ld\n", n->val.name, n->size);
						return n;
					}
				}
			} else if (n->type == FILE_REC_SYMLINK) {
				// DEBUG("f %s %s\n",n->val.name, p);
				len = strlen(n->val.symlink);
				if (strncmp(n->val.symlink, p, len) == 0) {
					if (*(p + len) == '\0') {
						// DEBUG("found symlink %s = %ld\n", n->val.name, n->size);
						return n;
					}
				}
			} else if (n->type == FILE_REC_SUBDIR) {
				// DEBUG("d %s %s\n",n->val.subdir->val.dir, p);
				len = strlen(n->val.subdir->val.dir);
				if (strncmp(n->val.subdir->val.dir, p, len) == 0) {
					if (*(p + len)=='/') {
						d = n->val.subdir;
						p += len + 1;
						break;
					} else if (*(p + len) == '\0') {
						// DEBUG("found dir %s\n", n->val.subdir->val.dir);
						return n->val.subdir;
					}
				}
			} else assert(0 && "unreachable place");
			n = n->next;
		} // while n
		if (!d) break;
	} // while
	// DEBUG("not found %s\n", path);
	return NULL;
} // find_file_record_for_path()

// FUSE operation: getattr
static int kavcachefs_getattr(const char *path, struct stat *stbuf,
		struct fuse_file_info *fi)
{
	(void) fi;
	int ret = -ENOENT; // default error

	// DEBUG("getattr: %s\n", path);

	struct remote_filesystem_st *fs = NULL;
	pthread_mutex_lock(&global_tree_mutex);
	fs = global_tree;
	pthread_mutex_unlock(&global_tree_mutex);
	if (!fs) return ret;

	memset(stbuf, 0, sizeof(struct stat));

	pthread_rwlock_rdlock(&fs->rwlock);
	if (!fs->root) goto exit;

	struct file_record_st *d = NULL;
	if (strcmp(path, "/") == 0) {
		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 2;
		stbuf->st_size = fs->root->size;
		stbuf->st_atime = fs->root->mtime;
		stbuf->st_mtime = fs->root->mtime;
		stbuf->st_ctime = fs->root->mtime;
		ret = 0;
		goto exit;
	} else {
		d = find_file_record_for_path(fs->root, path);
		if (!d) goto exit;
	};

	if (d->type == FILE_REC_FILE) {
		stbuf->st_mode = d->mode; // S_IFREG | 0444;
		stbuf->st_nlink = 1;
		stbuf->st_size = d->size;
		if (d->cache == FILE_IN_CACHE) {
			stbuf->st_blocks = (d->size / global_tree_block_size) * (global_tree_block_size / 512);
			if ((d->size % global_tree_block_size) > 0) stbuf->st_blocks += (global_tree_block_size / 512);
		} else stbuf->st_blocks = 0;
	} else if (d->type == FILE_REC_PARENTDIR) {
		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 2;
		stbuf->st_size = d->size;
//		if (d->cache == FILE_IN_CACHE) {
//		stbuf->st_blocks = d->size / global_tree_block_size;
//		if ((d->size % global_tree_block_size) > 0) stbuf->st_blocks += 1;
//		}
	} else if (d->type == FILE_REC_SYMLINK) {
		stbuf->st_mode = d->mode; // S_IFLNK | 0444;
		stbuf->st_nlink = 1;
		stbuf->st_size = strlen(d->val.symlink);
	} else goto exit;

	stbuf->st_blksize = 512;
	stbuf->st_ino = d->ino;
	stbuf->st_atime = d->atime;
	stbuf->st_mtime = d->mtime;
	stbuf->st_ctime = d->mtime;

	ret = 0;
exit:
	pthread_rwlock_unlock(&fs->rwlock);
	return ret;
} // kavcachefs_getattr()


#ifndef FUSE_FILL_DIR_DEFAULTS
#define FUSE_FILL_DIR_DEFAULTS 0
#endif

// FUSE operation: readdir
static int kavcachefs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		off_t offset, struct fuse_file_info *fi,
		enum fuse_readdir_flags flags)
{
	// DEBUG("readdir: %s\n", path);
	int ret = -ENOENT; // default error

	(void) offset;
	(void) fi;
	(void) flags;

	struct remote_filesystem_st *fs = NULL;
	pthread_mutex_lock(&global_tree_mutex);
	fs = global_tree;
	pthread_mutex_unlock(&global_tree_mutex);
	if (!fs) return ret;

	pthread_rwlock_rdlock(&fs->rwlock);
	if (!fs->root) goto exit;

	struct file_record_st *n = find_file_record_for_path(fs->root, path);
	if (!n) goto exit;

	if (n->type != FILE_REC_PARENTDIR) goto exit;
	struct file_record_st *find = n->next;

	filler(buf, ".", NULL, 0, FUSE_FILL_DIR_DEFAULTS);
	filler(buf, "..", NULL, 0, FUSE_FILL_DIR_DEFAULTS);
	while (find) {
		if (find->type == FILE_REC_FILE) {
			filler(buf, find->val.name, NULL, 0, FUSE_FILL_DIR_DEFAULTS);
		} else if (find->type == FILE_REC_SYMLINK) {
			filler(buf, find->val.symlink, NULL, 0, FUSE_FILL_DIR_DEFAULTS);
		} else if (find->type == FILE_REC_SUBDIR && find->val.subdir) {
			filler(buf, find->val.subdir->val.dir, NULL, 0, FUSE_FILL_DIR_DEFAULTS);
		}
		find = find->next;
	}
	ret = 0;

exit:
	pthread_rwlock_unlock(&fs->rwlock);
	return ret;
} // kavcachefs_readdir()

// FUSE operation: open
static int kavcachefs_open(const char *path, struct fuse_file_info *fi)
{
	// DEBUG("open: %s\n", path);
	int ret = -ENOENT; // default error

	struct remote_filesystem_st *fs = NULL;
	pthread_mutex_lock(&global_tree_mutex);
	fs = global_tree;
	pthread_mutex_unlock(&global_tree_mutex);
	if (!fs) return ret;

	pthread_rwlock_rdlock(&fs->rwlock);
	if (!fs->root) goto exit;

	struct file_record_st *n = find_file_record_for_path(fs->root, path);
	if (!n) goto exit;

	if ((fi->flags & O_ACCMODE) != O_RDONLY) ret = -EACCES;
exit:
	pthread_rwlock_unlock(&fs->rwlock);
	return 0;
} // kavcachefs_open()

// Try to find cached file by eviction rule for delete
struct file_record_st *find_evicted_file(struct remote_filesystem_st *fs) {
	struct file_record_st *ret = NULL;

	pthread_rwlock_rdlock(&fs->rwlock);
	if (options.eviction == EVICTION_RANDOM) {
		int rnd_file = 0;
		if (fs->cached_files > 0) {
			rnd_file = rand() % fs->cached_files;
			ret = fs->cached_list;
			while (ret && rnd_file > 0) {
				ret = ret->next_cached;
				rnd_file--;
			}
		}
	} else if (options.eviction == EVICTION_ATIME) {
		time_t min_atime = time(NULL);
		struct file_record_st *it = fs->cached_list;
		while (it) {
			if (it->atime < min_atime) {
				ret = it;
				min_atime = it->atime;
			}
			it = it->next_cached;
		}
	}
	pthread_rwlock_unlock(&fs->rwlock);

	return ret;
} // find_evicted_file()

// Build path to cached file in buffer
char *build_file_path(char *path, size_t path_size, size_t pos,
	struct file_record_st *dir, struct file_record_st *file
) {
	if (dir->type != FILE_REC_PARENTDIR) return NULL;
	struct file_record_st *it = dir->next;
	while (it) {
		if (it == file && it->type == FILE_REC_FILE) {
			snprintf(path + pos, path_size - pos, "/%s", it->val.name);
			return path;
		} else if (it->type == FILE_REC_SUBDIR) {
			size_t rpos = pos + snprintf(path + pos, path_size - pos, "/%s", it->val.subdir->val.dir);
			char *recurse = build_file_path(path, path_size, rpos, it->val.subdir, file);
			if (recurse) return recurse;
		}
		it = it->next;
	}
	*(path + pos) = '\0';
	return NULL;
} // build_file_path()

// Thread function for downloading file from remote dir to local
void *download_remote_file(void *data) {
	struct file_download_st *job = data;
	FILE *in = NULL;
	FILE *out = NULL;
	size_t download_size = 0;
	char read_path[PATH_MAX];
	char write_path[PATH_MAX];
	int eviction_count = 0;
	int can_download = 0;
	int file_too_big = 0;

	// check download list for this file (if already in queue)
	pthread_mutex_lock(&job->filesystem->download_mutex);
	struct file_download_st *already_go = job->filesystem->download_list;
	while (already_go) {
		if (strcmp(already_go->name, job->name) == 0) break;
		already_go = already_go->next;
	}
	if (already_go) {
		DEBUG("job %s already in list\n", job->name);
		pthread_mutex_unlock(&job->filesystem->download_mutex);
		goto exit;
	} else {
		job->prev = NULL;
		job->next = job->filesystem->download_list;
		if (job->filesystem->download_list)
			job->filesystem->download_list->prev = job;
		job->filesystem->download_list = job;
		job->filesystem->download_need_space += job->rec->size;
	}
	pthread_mutex_unlock(&job->filesystem->download_mutex);
	// check free space on local dir fs
	struct statfs lfs;
	snprintf(write_path, sizeof(write_path), "%s", options.local);

eviction_repeat:
	can_download = 0;
	if (statfs(write_path, &lfs) != 0) {
		DEBUG("cant statfs on %s\n", write_path);
		goto remove_from_list;
	}
	pthread_mutex_lock(&job->filesystem->download_mutex);
	if (job->filesystem->download_need_space < lfs.f_bsize * lfs.f_bavail) {
		can_download = 1;
	} else if (job->rec->size > lfs.f_bsize * lfs.f_blocks) {
		file_too_big = 1;
	}
	pthread_mutex_unlock(&job->filesystem->download_mutex);

	if (file_too_big) {
		DEBUG("file too big for download in local filesystem (need=%ld, bsize=%ld blocks=%ld)\n",
			job->rec->size, lfs.f_bsize, lfs.f_blocks);
		goto remove_from_list;
	}

	if (can_download == 0) {
		// evict cached file for clean space
		if (
			options.eviction == EVICTION_ATIME
			|| options.eviction == EVICTION_RANDOM
		) {
			struct file_record_st *evicted_file = find_evicted_file(job->filesystem);
			if (evicted_file) {
				// DEBUG("found evicted file %s\n", evicted_file->val.name);
				size_t len = snprintf(read_path, sizeof(read_path), "%s", options.local);
				char *del = build_file_path(read_path, sizeof(read_path), len, job->filesystem->root, evicted_file);
				// if (del) DEBUG("EVICTION file %s\n", del);
				if (del && unlink(del) == 0) {
					DEBUG("DELETE #%d evicted file %s = %ld\n", eviction_count, del, evicted_file->size);

					pthread_rwlock_wrlock(&job->filesystem->rwlock);
					evicted_file->cache = FILE_NOT_IN_CACHE;
					job->filesystem->cached_files--;
					job->filesystem->cached_size -= evicted_file->size;
					job->filesystem->evicted_files++;
					job->filesystem->evicted_size += evicted_file->size;

					// remove evicted file from cached list
					if (!evicted_file->prev_cached)
						job->filesystem->cached_list = evicted_file->next_cached;
					else
						evicted_file->prev_cached->next_cached = evicted_file->next_cached;
					if (evicted_file->next_cached)
						evicted_file->next_cached->prev_cached = evicted_file->prev_cached;
					evicted_file->prev_cached = NULL;
					evicted_file->next_cached = NULL;

					pthread_rwlock_unlock(&job->filesystem->rwlock);

					eviction_count++;
					if (eviction_count < options.eviction_try) goto eviction_repeat;
				}
			}
		}
		DEBUG("no more space in local filesystem (need=%ld, bsize=%ld bfree=%ld bavail=%ld)\n",
			job->rec->size, lfs.f_bsize, lfs.f_bfree, lfs.f_bavail);
		goto remove_from_list;
	}

	snprintf(read_path, sizeof(read_path), "%s%s", options.remote, job->name);
	snprintf(write_path, sizeof(write_path), "%s%s", options.local, job->name);

	DEBUG("download:\n\tfrom: %s\n\tto: %s\n", read_path, write_path);

	// create destination path as "mkdir -p"
	char *slash = strchr(write_path,'/');
	while (slash) {
		*slash = '\0';
		if (access(write_path, R_OK | W_OK |  X_OK) != 0) {
			mkdir(write_path, S_IRWXU);
		}
		*slash = '/';
		slash = strchr(slash + 1, '/');
	};

	// open remote file
	in = fopen(read_path, "rb");
	if (!in) {
		DEBUG("cant open file %s\n", read_path);
		//TODO remove job->rec from cache file tree
		goto remove_from_list;
	}

	// open local file
	out = fopen(write_path, "wb");
	if (!out) {
		DEBUG("cant create file %s\n", write_path);
		goto remove_from_list;
	}

	// save file remote file modif time
	struct stat fst;
	int stat_ok = 0;
	if (stat(read_path, &fst) == 0) stat_ok = 1;

	pthread_rwlock_wrlock(&job->filesystem->rwlock);
	job->rec->cache = FILE_IN_DOWNLOADING;
	pthread_rwlock_unlock(&job->filesystem->rwlock);

#ifndef _SYS_SENDFILE_H
	do {
		// use read_path as copy buffer
		size_t r = fread(read_path, 1, sizeof(read_path), in);
		size_t w = fwrite(read_path, 1, r, out);
		DEBUG("copy %s = %ld buffer\n", job->name, w);
		if (w != r) goto remove_fail;
		download_size += w;
	} while (!feof(in));
#else
	off_t offs = 0;
	ssize_t sended = 0;
	do {
		sended = sendfile(fileno(out), fileno(in), &offs, job->rec->size - offs);
		DEBUG("sendfile %s = %ld\n", job->name, sended);
		if (sended == -1) break;
		download_size += sended;
	} while (download_size != job->rec->size);
	if (sended == -1) {
		DEBUG("sendfile failure, error = %d\n", errno);
		goto remove_fail;
	}
#endif
	if (in) { fclose(in); in = NULL; }
	if (out) { fclose(out); out = NULL; }

	// restore times on local file
	if (stat_ok) {
		struct timeval tim[2] = {0};
		tim[0].tv_sec = fst.st_atime;
		tim[1].tv_sec = fst.st_mtime;
		if (utimes(write_path, tim) == 0) {
			DEBUG("modify time %s\n", write_path);
		};
	}

	// add file in cached list
	pthread_rwlock_wrlock(&job->filesystem->rwlock);
	job->rec->cache = FILE_IN_CACHE;
	job->filesystem->downloaded_files++;
	job->filesystem->downloaded_size += fst.st_size;
	job->filesystem->cached_files++;
	job->filesystem->cached_size += fst.st_size;
	job->rec->prev_cached = NULL;
	job->rec->next_cached = job->filesystem->cached_list;
	if (job->filesystem->cached_list)
		job->filesystem->cached_list->prev_cached = job->rec;
	job->filesystem->cached_list = job->rec;
	if (stat_ok) {
		job->rec->atime = fst.st_atime;
		job->rec->mtime = fst.st_mtime;
	}
	pthread_rwlock_unlock(&job->filesystem->rwlock);

	DEBUG("download file %s = %ld OK\n", job->name, download_size);

	goto remove_from_list;

remove_fail:
	if (in) { fclose(in); in = NULL; }
	if (out) { fclose(out); out = NULL; }
	pthread_rwlock_wrlock(&job->filesystem->rwlock);
	job->rec->cache = FILE_NOT_IN_CACHE;
	pthread_rwlock_unlock(&job->filesystem->rwlock);
	unlink(write_path);

remove_from_list:
	pthread_mutex_lock(&job->filesystem->download_mutex);
	job->filesystem->download_need_space -= job->rec->size;
	DEBUG("remove job from list %s (need space=%ld)\n",
		job->name, job->filesystem->download_need_space);
	if (!job->prev)
		job->filesystem->download_list = job->next;
	else
		job->prev->next = job->next;
	if (job->next) job->next->prev = job->prev;
	job->next = NULL;
	job->prev = NULL;
	pthread_mutex_unlock(&job->filesystem->download_mutex);
	goto exit;

exit:
	if (in) fclose(in);
	if (out) fclose(out);
	free(job->name);
	free(job);
	pthread_exit(NULL);
} // download_remote_file()

// FUSE operation: read
static int kavcachefs_read(const char *path, char *buf, size_t size,
		off_t offset, struct fuse_file_info *fi)
{
	// DEBUG("read: %s size=%ld offs=%ld\n", path, size, offset);

	(void) fi;
	char read_path[PATH_MAX];

	struct remote_filesystem_st *fs = NULL;
	pthread_mutex_lock(&global_tree_mutex);
	fs = global_tree;
	pthread_mutex_unlock(&global_tree_mutex);
	if (!fs) return 0;

	int ret = 0;
	int cache_state = 0;
	pthread_rwlock_rdlock(&fs->rwlock);
	struct file_record_st *n = find_file_record_for_path(fs->root, path);
	if (!n) ret = 1;
	else {
		cache_state = n->cache;
		if (n->type != FILE_REC_FILE || offset > n->size) ret = 1;
	}
	pthread_rwlock_unlock(&fs->rwlock);
	if (ret == 1) return 0;

	// path start from '/' char
	if (cache_state != FILE_IN_CACHE) {
		snprintf(read_path, sizeof(read_path), "%s%s", options.remote, path);
	} else {
		snprintf(read_path, sizeof(read_path), "%s%s", options.local, path);
	}

	FILE *f = fopen(read_path,"rb");
	if (f) {
		if (
			cache_state == FILE_NOT_IN_CACHE
			&& global_localfs_size > n->size
		) {
			struct file_download_st *job = calloc(1, sizeof(struct file_download_st));
			if (job) {
				job->filesystem = fs;
				job->rec = n;
				job->name = strdup(path);
				if (job->name) {
					pthread_t th;
					int r = pthread_create(&th, NULL, download_remote_file, (void *)job);
					if (r == 0) {
						// DEBUG("create download thread for %s\n", path);
						r = pthread_detach(th);
					} else {
						free(job->name);
						free(job);
					}
				} else {
					free(job);
				}
			}
		}

		if (0 == fseek(f, offset, SEEK_SET)) {
			size = fread(buf, 1, size, f);
		} else size = 0;
		fclose(f);
	} else size = 0;

	pthread_rwlock_wrlock(&fs->rwlock);
	n->atime = time(NULL);
	pthread_rwlock_unlock(&fs->rwlock);
	DEBUG("read data from %s, offset=%ld size=%ld\n", read_path, offset, size);

	return size;
} // kavcachefs_read()

static int kavcachefs_readlink(const char *path, char *buf, size_t size)
{
	struct remote_filesystem_st *fs = NULL;
	pthread_mutex_lock(&global_tree_mutex);
	fs = global_tree;
	pthread_mutex_unlock(&global_tree_mutex);
	if (!fs) return -1;

	pthread_rwlock_rdlock(&fs->rwlock);
	struct file_record_st *n = find_file_record_for_path(fs->root, path);
	pthread_rwlock_unlock(&fs->rwlock);
	if (!n) return -1;

	if (n->type != FILE_REC_SYMLINK) return -1;

	memcpy(buf, &(*n->val.symlink) + strlen(n->val.symlink) + 1, n->size + 1);

	return 0;
} // kavcachefs_readlink()

// recursively read directory
struct file_record_st *recurse_read_dir(char *path, size_t path_size,
	size_t remotelen, struct remote_filesystem_st *fs)
{
	char base_path[PATH_MAX];
	char local_path[PATH_MAX];
	struct stat fst;

	size_t pos = strlen(path);

	// DEBUG("scan directory %s\n", path);

	size_t dir_size = 0;
	DIR *dir = opendir(path);
	struct dirent *entry;
	if (!dir) {
		DEBUG("can't open dir %s: %s", path, strerror(errno));
		return NULL;
	}

	struct file_record_st *dirholder = calloc(1, sizeof(struct file_record_st));
	if (!dirholder) goto exit;

	strcpy(base_path, path);
	dirholder->val.dir = strdup(basename(base_path));
	if (!dirholder->val.dir) { free(dirholder); dirholder = NULL; goto exit; }
	dirholder->type = FILE_REC_PARENTDIR;
	while ((entry = readdir(dir)) != NULL) {
		if (strcmp(entry->d_name,".") == 0 || strcmp(entry->d_name,"..") == 0) continue;

		// DEBUG("name %s = type %d\n", entry->d_name, entry->d_type);

		if (snprintf(path + pos, path_size - pos,
			"/%s", entry->d_name) == strlen(entry->d_name) + 1)
		{
			if (entry->d_type == DT_LNK) {
				if (lstat(path, &fst) != 0) continue;
			} else {
				if (stat(path, &fst) != 0) continue;
			}

			struct file_record_st *rec = calloc(1, sizeof(struct file_record_st));
			if (!rec) continue;

			if (S_ISREG(fst.st_mode) && !S_ISLNK(fst.st_mode)) {
				rec->val.name = strdup(entry->d_name);
				if (!rec->val.name) { free(rec); continue; }
				dir_size += fst.st_size;
				rec->size = fst.st_size;
				rec->type = FILE_REC_FILE;
				fs->total_files++;
				// check already loaded
				snprintf(local_path, sizeof(local_path), "%s%s", options.local, path + remotelen);
				if (access(local_path, F_OK) == 0) {
					DEBUG("check file %s", local_path);
					struct stat fstloc;
					if (stat(local_path, &fstloc) == 0) {
						if (fstloc.st_size == fst.st_size && fstloc.st_mtime == fst.st_mtime) {
							DEBUG(" = %ld OK\n", fstloc.st_size);
							rec->cache = FILE_IN_CACHE;
							fs->cached_files++;
							fs->cached_size += fstloc.st_size;

							rec->prev_cached = NULL;
							rec->next_cached = fs->cached_list;
							if (fs->cached_list) fs->cached_list->prev_cached = rec;
							fs->cached_list = rec;
						} else {
							if (unlink(local_path) == 0) {
								DEBUG(" = %ld DELETED\n", fstloc.st_size);
							} else {
								DEBUG(" = %ld FAILED\n", fstloc.st_size);
							};
						}
					}
				}
			} else if (S_ISDIR(fst.st_mode) && !S_ISLNK(fst.st_mode)) {
				rec->val.subdir = recurse_read_dir(path, path_size, remotelen, fs);
				if (!rec->val.subdir) { free(rec); continue; }
				rec->val.subdir->atime = fst.st_atime;
				rec->val.subdir->mtime = fst.st_mtime;
				dir_size += rec->val.subdir->size;
				rec->type = FILE_REC_SUBDIR;
				fs->total_dirs++;
			} else if (S_ISLNK(fst.st_mode)) {
				size_t l = strlen(entry->d_name);
				rec->val.symlink = calloc(1, l + fst.st_size + 3);
				if (!rec->val.symlink) { free(rec); continue; }
				rec->size = fst.st_size;
				strcpy(rec->val.symlink, entry->d_name);
				if (readlink(path, rec->val.symlink + l + 1, fst.st_size + 1) == fst.st_size) {
					*(rec->val.symlink + l + 1 + fst.st_size + 1) = '\0';
					// DEBUG("add symlink %s, size=%ld, value=%s\n",rec->val.symlink, fst.st_size, &(*rec->val.symlink) + l + 1);
					rec->type = FILE_REC_SYMLINK;
					fs->total_symlinks++;
				} else {
					free(rec->val.symlink);
					free(rec);
					continue;
				}
			} else {
				DEBUG("unknown %s, mode %d\n", path, fst.st_mode);
				free(rec); continue;
			}

			rec->mode = fst.st_mode;
			rec->atime = fst.st_atime;
			rec->mtime = fst.st_mtime;
			rec->ino = fs->next_inode++;
			fs->total_size += fst.st_size;

			rec->next = dirholder->next;
			dirholder->next = rec;
		}
	}
exit:
	closedir(dir);

	if (dirholder) dirholder->size = dir_size;

	// restore path after recursion
	*(path + pos) = '\0';
	return dirholder;
} // recurse_read_dir()

// Clean local dir from trash files
int clean_localdir_from_trash_files(char *path, size_t path_size, size_t remotelen, struct file_record_st *root) {
	// DEBUG("clean %s\n", path);

	DIR *dir;
	struct dirent *entry;
	size_t pos = strlen(path);

	dir = opendir(path);
	if (!dir) return 0;

	size_t files_in_dir = 0;
	size_t deleted = 0;
	while ( (entry = readdir(dir)) != NULL) {
		if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
		files_in_dir++;
		snprintf(path + pos, PATH_MAX - pos, "/%s", entry->d_name);

		if (entry->d_type == DT_REG) {
			struct file_record_st *n = find_file_record_for_path(root, path + remotelen);
			if (!n) {
				if (unlink(path) == 0) {
					DEBUG("%s DELETED\n", path);
					deleted++;
				} else {
					DEBUG("%s delete FAILED\n", path);
				};
			} else {
				// DEBUG("check file %s\n", path + remotelen);
			}
		} else if (entry->d_type == DT_DIR) {
			// DEBUG("recurse to dir %s\n", path);
			deleted += clean_localdir_from_trash_files(path, PATH_MAX, remotelen, root);
		};
	};
	closedir(dir);
	*(path + pos) = '\0';

	// delete empty directories
	if (files_in_dir == deleted && strlen(path + remotelen) > 0) {
		if (rmdir(path) == 0) {
			// DEBUG("delete empty dir %s\n", path);
			return 1;
		};
	}
	return 0;
} // clean_localdir_from_trash_files()

// Clean memory from remote filesystem tree
int clean_memory_from_remotefs(struct file_record_st *fs) {
	struct file_record_st *p = fs, *t;
	while (p) {
		switch (p->type) {
			case FILE_REC_FILE: {
				if (p->val.name) free(p->val.name);
			} break;
			case FILE_REC_SYMLINK: {
				if (p->val.symlink) free(p->val.symlink);
			} break;
			case FILE_REC_PARENTDIR: {
				if (p->val.dir) free(p->val.dir);
			} break;
			case FILE_REC_SUBDIR: {
				if (p->val.subdir) clean_memory_from_remotefs(p->val.subdir);
			} break;
			default: break;
		}
		t = p;
		p = p->next;
		free(t);
	};
	return 0;
} // clean_memory_from_remotefs()

void *thread_garbage_fs_cleaner(void *data) {
	char local_path[PATH_MAX];

	DEBUG("thread_garbage_fs_cleaner start\n");

	// Free memory
	struct remote_filesystem_st *t = data;
	sleep(1);

	do {
		int need_wait = 0;
		pthread_mutex_lock(&t->download_mutex);
			if (t->download_list) need_wait = 1;
		pthread_mutex_unlock(&t->download_mutex);
		if (need_wait) sleep(1); else break;
	} while (1);

	pthread_rwlock_wrlock(&t->rwlock);
	if (t->root) {
		clean_memory_from_remotefs(t->root);
	}
	pthread_rwlock_unlock(&t->rwlock);
	free(t);

	// Clean local filesystem from removed files on remote
	struct file_record_st *tree = NULL;
	pthread_mutex_lock(&global_tree_mutex);
	if (global_tree) tree = global_tree->root;
	pthread_mutex_unlock(&global_tree_mutex);
	if (tree) {
		snprintf(local_path, PATH_MAX, "%s", options.local);
		clean_localdir_from_trash_files(local_path, PATH_MAX, strlen(options.local), tree);
	}

	pthread_exit(NULL);
} // clean_memory_from_remotefs()

// Read remote filesystem tree in memory
int update_cache_from_remote_dir() {
	char work_path[PATH_MAX];
	struct remote_filesystem_st *new_fs = calloc(1, sizeof(struct remote_filesystem_st));
	if (!new_fs) return -1;
	DEBUG("update cache from remote dir\n");

	snprintf(work_path, sizeof(work_path), "%s", options.remote);

	new_fs->root = NULL;
	new_fs->next_inode = 1;
	new_fs->total_size = 0;
	new_fs->total_dirs = 0;
	new_fs->total_files = 0;
	new_fs->total_symlinks = 0;
	new_fs->downloaded_files = 0;
	new_fs->downloaded_size = 0;
	new_fs->cached_files = 0;
	new_fs->cached_size = 0;
	new_fs->evicted_files = 0;
	new_fs->evicted_size = 0;
	new_fs->download_need_space = 0;
	new_fs->cached_list = NULL;
	pthread_rwlock_init(&new_fs->rwlock, NULL);
	pthread_mutex_init(&new_fs->download_mutex, NULL);

	new_fs->root = recurse_read_dir(work_path, sizeof(work_path), strlen(options.remote), new_fs);
	if (new_fs->root) {
		struct statfs lfs;
		snprintf(work_path, sizeof(work_path), "%s", options.local);
		struct remote_filesystem_st *temp = NULL;
		pthread_mutex_lock(&global_tree_mutex);
			if (statfs(work_path, &lfs) == 0) {
				new_fs->block_size = lfs.f_bsize;
				global_localfs_size = lfs.f_bsize * lfs.f_blocks;
			} else {
				new_fs->block_size = 512; // unknown
				global_localfs_size = 0;
			}
			temp = global_tree;
			global_tree = new_fs;
			global_tree_block_size = new_fs->block_size;
		pthread_mutex_unlock(&global_tree_mutex);

		if (temp) {
			pthread_t th;
			int r = pthread_create(&th, NULL, thread_garbage_fs_cleaner, (void *)temp);
			if (r == 0) {
				DEBUG("create clean memory thread\n");
				r = pthread_detach(th);
			}
		}

		return 0;
	} else {
		free(new_fs);
		return -2;
	}
}

static void show_help(const char *progname)
{
	printf("Read-only cache file system based on FUSE. Author: Kuzin Andrey <kuzinandrey@yandex.ru>\n"
		"\nUsage: %s [options] <mountpoint>\n"
		"\nOptions:\n"
		"    --remote=<s>       mount point of remote file system (nfs, cifs, sshfs)\n"
		"    --local=<s>        local mount point for store cached files\n"
		"    --eviction=<s>     remove cached files for get free space (no, random, atime)\n"
		"\nDescription:\n"
		"    %s this is read-only cache file system based on FUSE.\n"
		"    At start it read remote file system directory and emulate its content in <mountpoint>.\n"
		"    Any read operation start background copy process from remote to local dir for not cached files.\n"
		"    For already cached files all read operation make from local directory.\n"
		"    Eviction rules to clean space if no any free space for download:\n"
		"    no - store permanent, random - delete random file, atime - find old file by access time\n"
		"\nSignals:\n"
		"    USR1 - reload content of remote directory\n"
	, progname, progname);
}

void signal_handler(int sig) {
	switch (sig) {
		case SIGUSR1:
			update_cache_from_remote_dir();
		break;
	} // swtich
} // signal_handler

// kavcachefs operations
static const struct fuse_operations kavcachefs_operations = {
	.init = kavcachefs_init,
	.getattr = kavcachefs_getattr,
	.readdir = kavcachefs_readdir,
	.readlink= kavcachefs_readlink,
	.open = kavcachefs_open,
	.read = kavcachefs_read,
};

int main(int argc, char *argv[]) {
	int ret = 1; // default error
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
	// struct stat stbuf;

	tzset();
	global_start_time = time(NULL);
	srand(global_start_time);

	// parse options
	if (fuse_opt_parse(&args, &options, option_spec, NULL) == -1) goto exit;

	if (options.show_help) {
		show_help(argv[0]);
		assert(fuse_opt_add_arg(&args, "--help") == 0);
		args.argv[0][0] = '\0';
		ret = 0;
		goto exit;
	}

	if (!options.remote) {
		fprintf(stderr, "Option %s is not defined\n", "--remote");
		ret = 1; goto exit;
	} else {
		if (access(options.remote, R_OK | X_OK) != 0) {
			fprintf(stderr,"Can't read at %s\n", options.remote);
			ret = 2; goto exit;
		}
	}

	if (!options.local) {
		fprintf(stderr, "Option %s is not defined\n", "--local");
		ret = 1; goto exit;
	} else {
		if (access(options.local, W_OK | R_OK | X_OK) != 0) {
			fprintf(stderr,"Can't write at %s\n", options.local);
			ret = 2; goto exit;
		}
	}

	if (!options.eviction_cli) {
		options.eviction = EVICTION_NO;
	} else {
		if (strcasecmp(options.eviction_cli,"no") == 0) {
			options.eviction = EVICTION_NO;
		} else if (strcasecmp(options.eviction_cli,"random") == 0) {
			options.eviction = EVICTION_RANDOM;
		} else if (strcasecmp(options.eviction_cli,"atime") == 0) {
			options.eviction = EVICTION_ATIME;
		} else {
			options.eviction = EVICTION_UNKNOWN;
			fprintf(stderr, "Ignore unknown eviction value: %s\n", options.eviction_cli);
		}
	}

	printf("Work with options:\n");
	printf("  remote: %s\n", options.remote);
	printf("  local: %s\n", options.local);
	printf("  eviction: %s\n", eviction_enum_string(options.eviction));
	if (options.eviction != EVICTION_NO)
		printf("  eviction try: %d\n", options.eviction_try);

	ret = update_cache_from_remote_dir();
	if(ret != 0) {
		fprintf(stderr, "Update remote directory failed with %d\n", ret);
		goto exit;
	}

	if (global_tree) {
		printf("Remote filesystem stat:\n");
		printf("\tTotal size: %ld\n", global_tree->total_size);
		printf("\tDirs: %ld\n", global_tree->total_dirs);
		printf("\tFiles: %ld\n", global_tree->total_files);
		printf("\tSymlinks: %ld\n", global_tree->total_symlinks);
		printf("Already cached:\n");
		printf("\tFiles: %ld\n", global_tree->cached_files);
		printf("\tSize: %ld\n", global_tree->cached_size);
		printf("\tLocal dir space: %ld\n", global_localfs_size);

		if (global_tree->root) {
			char local_path[PATH_MAX];
			snprintf(local_path, PATH_MAX, "%s", options.local);
			clean_localdir_from_trash_files(local_path, PATH_MAX,
				strlen(options.local), global_tree->root);
		}
	}

	signal(SIGUSR1, signal_handler);
	DEBUG("start kavcachefs filesystem\n");
	ret = fuse_main(args.argc, args.argv, &kavcachefs_operations, NULL);

exit:
	DEBUG("clean all\n");
	if (global_tree && global_tree->root) {
		clean_memory_from_remotefs(global_tree->root);
		free(global_tree);
	}
	if (options.remote) free(options.remote);
	if (options.local) free(options.local);
	if (options.eviction_cli) free(options.eviction_cli);
	fuse_opt_free_args(&args);

	return ret;
}
