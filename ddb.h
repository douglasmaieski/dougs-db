/*
  Written by Douglas Maieski - https://github.com/douglasmaieski/
*/


#ifndef DOUGS_DB_H
#define DOUGS_DB_H

#include "gtw.h"
#include "linked_list.h"
#include "avl_tree.h"
#include <fcntl.h>

struct ddb_result {
  unsigned long start;
  unsigned long pos;
  unsigned long size;
  struct ddb *ddb;
};

struct ddb_node {
  unsigned char hash[32];
  unsigned long content;
  unsigned long size;
  unsigned long left;
  unsigned long right;
  unsigned long parent;
  unsigned long key_len;
  unsigned char key[];
};

struct ddb_meta {
  unsigned long salt[2];
  unsigned long root_ptr;
  unsigned long file_ptr;
  unsigned long _unused[4];
  char _pad[4096 - 64];
};

struct ddb_route {
  unsigned long id[4];
  unsigned long addr;
  struct ddb_route *parent;
  struct ddb_route *left;
  struct ddb_route *right;
  unsigned int level;
  int lock;
};

struct ddb {
  struct ddb_meta meta;
  long dbfd;
  long dirfd;
  unsigned long bsize;
  struct list cache_list;
  struct avl_tree_node *cache_root;
  int lock;
  int map_lock;
  struct ddb_route *route_root;
  volatile unsigned long route_pos;
  struct ddb_route map[1<<17];
};

long ddb_create(const char *name, unsigned long initial_size);

long ddb_open_sync(struct ddb *ddb,
                   const char *path,
                   int dirfd,
                   unsigned long cached_blocks);

long ddb_upsert(struct ddb *ddb,
                const void *key,
                unsigned long key_len,
                const void *data,
                unsigned long data_len,
                struct gt_w *w);

long ddb_delete(struct ddb *ddb,
                const void *key,
                unsigned long key_len,
                struct gt_w *w);

long ddb_find(struct ddb_result *res,
              struct ddb *ddb,
              const void *key,
              unsigned long key_len,
              struct gt_w *w);

long ddb_read(struct ddb_result *res,
              void *dest,
              unsigned long len,
              struct gt_w *w);

long ddb_restart_after_failure(struct ddb *ddb, struct gt_w *w);

#endif