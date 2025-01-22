/*
  Written by Douglas Maieski - https://github.com/douglasmaieski/
*/


#define _GNU_SOURCE

#include "ddb.h"
#include "gtw.h"
#include "thread.h"
#include "base.h"

#include <assert.h>
#include <sys/random.h>
#include <openssl/sha.h>
#include <sys/statvfs.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>

struct cache_node {
  struct list_node list_node;
  struct avl_tree_node avl_node;
  unsigned long idx;
  void *data;
  int lock;
};

static int avl_cmp(const struct avl_tree_node *node1,
                   const struct avl_tree_node *node2)
{
  struct cache_node *a = MEMBER_TO_PARENT(struct cache_node, node1, avl_node);
  struct cache_node *b = MEMBER_TO_PARENT(struct cache_node, node2, avl_node);

  if (a->idx < b->idx)
    return -1;

  if (a->idx > b->idx)
    return 1;

  return 0;
}

static void compute_hash(void *dest,
                         struct ddb *ddb,
                         const void *key,
                         unsigned long key_len)
{
  SHA256_CTX ctx;
  SHA256_Init(&ctx);
  SHA256_Update(&ctx, key, key_len);
  SHA256_Update(&ctx, ddb->meta.salt, 16);
  SHA256_Final(dest, &ctx);
}

long ddb_create(const char *name, unsigned long initial_size)
{
  int fd = open(name, O_CREAT|O_RDWR, 0600);
  if (fd == -1)
    return 0;

  fallocate(fd, 0, 0, initial_size);

  char salt[16];
  getrandom(salt, 16, 0);

  write(fd, salt, 16);

  unsigned long ptr = 4096;
  write(fd, &ptr, 8);

  ptr = 4096 + 80; 
  write(fd, &ptr, 8);

  lseek(fd, 4096, SEEK_SET);

  struct ddb_node root;
  memset(&root, 0, sizeof root);
  getrandom(root.hash, 32, 0);
  root.content = 4096 + 80;
  write(fd, &root, 80);

  return 1;
}

long ddb_open_sync(struct ddb *ddb,
                   const char *path,
                   int dirfd,
                   unsigned long cached_blocks)
{
  ddb->dirfd = dirfd;
  ddb->dbfd = openat(dirfd, path, O_RDWR|O_DIRECT);
  if (ddb->dbfd < 0)
    return 0;

  struct statvfs st;
  statvfs(path, &st);
  ddb->bsize = st.f_bsize;

  if (read(ddb->dbfd, &ddb->meta, ddb->bsize) != ddb->bsize) {
    close(ddb->dbfd);
    return 0;
  }

  list_init(&ddb->cache_list);
  ddb->cache_root = NULL;

  char *mem = malloc(ddb->bsize * (cached_blocks + 1));
  if (!mem) {
    close(ddb->dbfd);
    return 0;
  }

  char *node_mem = malloc(sizeof(struct cache_node) * cached_blocks);
  if (!node_mem) {
    free(mem);
    close(ddb->dbfd);
    return 0;
  }

  unsigned long aligned = (unsigned long)mem;
  aligned += ddb->bsize - 1;
  aligned /= ddb->bsize;
  aligned *= ddb->bsize;

  mem = (char*)aligned;

  for (unsigned long i = 0; i < cached_blocks; ++i) {
    struct cache_node *cache_node = (struct cache_node*)(node_mem
                                                        + sizeof *cache_node * i);

    cache_node->lock = 0;
    cache_node->data = mem + (i * ddb->bsize);
    cache_node->idx = 0xffffffffffffffff - i;

    list_push_back(&ddb->cache_list, &cache_node->list_node);
    avl_tree_insert(&ddb->cache_root, &cache_node->avl_node, avl_cmp);
  }

  ddb->route_root = NULL;
  ddb->route_pos = 0;

  ddb->lock = 0;

  return 1;
}

static struct cache_node *load_page(struct ddb *ddb,
                                    unsigned long idx,
                                    struct gt_w *w)
{
  struct cache_node tmp;
  tmp.idx = idx;


  while (!try_lock(&ddb->lock)) {
    gt_w_nop(w);
  }

  struct avl_tree_node *node = avl_tree_lookup_node(ddb->cache_root,
                                                    &tmp.avl_node,
                                                    avl_cmp);
  struct cache_node *cache_node; 

  if (node) {
    cache_node = MEMBER_TO_PARENT(struct cache_node, node, avl_node);

    while (cache_node->lock) {
      // if the node is locked, then its contents are in use
      gt_w_nop(w);
    }

    list_remove(&ddb->cache_list, &cache_node->list_node);

    list_push_back(&ddb->cache_list, &cache_node->list_node);
  }
  else {
    struct cache_node *old = MEMBER_TO_PARENT(struct cache_node,
                                              ddb->cache_list.head,
                                              list_node);

    old->idx = idx;

    gt_w_read(w, ddb->dbfd, idx * ddb->bsize, old->data, ddb->bsize);

    list_remove(&ddb->cache_list, &old->list_node);

    list_push_back(&ddb->cache_list, &old->list_node);

    avl_tree_remove(&ddb->cache_root, &old->avl_node);

    avl_tree_insert(&ddb->cache_root, &old->avl_node, avl_cmp);

    cache_node = old;
  }

  unlock(&ddb->lock);

  return cache_node;
}

static long _write(struct ddb *ddb,
                   void *aligned_buf,       // must be 1x bsize minimum
                   unsigned long offset,
                   const void *data,        // doesn't have to be aligned
                   unsigned long data_len,
                   struct gt_w *w)
{
  // read first
  unsigned long pos = offset - (offset % ddb->bsize);
  unsigned long idx = pos / ddb->bsize;
  offset = offset % ddb->bsize;

  long r;
  while (data_len > 0) {
    struct cache_node *node = load_page(ddb, idx, w);

    while (!try_lock(&node->lock)) {
      gt_w_nop(w);
    }

    char *data1 = node->data;
    unsigned long n = ddb->bsize - offset;
    unsigned long avail = n < data_len ? n : data_len;
    memcpy(data1 + offset, data, avail);

    r = gt_w_write(w, ddb->dbfd, pos, data1, ddb->bsize);

    unlock(&node->lock);

    if (r != ddb->bsize)
      goto err;

    data = (char *)data + avail;
    pos += ddb->bsize;
    ++idx;
    data_len -= avail;
    offset = 0;
  }

  return 1;

err:
  return 0;
}

static long _read(struct ddb *ddb,
                  void *aligned_buf,
                  unsigned long offset,
                  void *dest,
                  unsigned long dest_len,
                  struct gt_w *w)
{
  unsigned long aligned_off = offset - (offset % ddb->bsize);
  long r;
  while (dest_len) {
    struct cache_node *node = load_page(ddb, aligned_off / ddb->bsize, w);

    while (!try_lock(&node->lock)) {
      gt_w_nop(w);
    }

    char *mem = node->data;

    unsigned long n = ddb->bsize - (offset % ddb->bsize);
    unsigned long avail = n > dest_len ? dest_len : n;

    memcpy(dest, mem + ddb->bsize - n, avail);

    unlock(&node->lock);

    dest = (char*)dest + avail;
    dest_len -= avail;
    aligned_off += ddb->bsize;
    offset = aligned_off;
  }

  return 1;

err:
  return 0;
}

static struct ddb_route *_find_route(struct ddb *ddb,
                                     unsigned char id[32],
                                     struct gt_w *w)
{
  while (!try_lock(&ddb->map_lock)) {
    gt_w_nop(w);
  }

  struct ddb_route *node = ddb->route_root;
  if (!node) {
    unlock(&ddb->map_lock);
    return NULL;
  }

  while (!try_lock(&node->lock)) {
    gt_w_nop(w);
  }

  unlock(&ddb->map_lock);

  while (node) {
    int diff = memcmp(id, node->id, 32);

    if (diff < 0) {
      struct ddb_route *next = node->left;
      if (next) {
        while (!try_lock(&next->lock)) {
          gt_w_nop(w);
        }

        unlock(&node->lock);
      }
      else
        break;

      node = next;
    }

    else if (diff > 0) {
      struct ddb_route *next = node->right;
      if (next) {
        while (!try_lock(&next->lock)) {
          gt_w_nop(w);
        }

        unlock(&node->lock);
      }
      else 
        break;


      node = next;
    }

    else
      break;
  }

  return node;
}

static long _append_route(struct ddb *ddb,
                          struct ddb_route *route,
                          struct gt_w *w)
{
  while (!try_lock(&route->lock)) {
    gt_w_nop(w);
  }

  assert(route->addr != 0);

  struct ddb_route *node = ddb->route_root;

  if (!node) {
    ddb->route_root = route;
    route->level = 0;
    unlock(&route->lock);
    return 1;
  }

  while (!try_lock(&node->lock)) {
    gt_w_nop(w);
  }

  route->level = 1;

  while (node) {
    int diff = memcmp(route->id, node->id, 32);

    if (diff < 0) {
      if (!node->left) {
        node->left = route;

        route->parent = node;
        route->left = NULL;
        route->right = NULL;

        unlock(&node->lock);
        unlock(&route->lock);

        return 1;
      }
      else {
        struct ddb_route *next = node->left;

        while (!try_lock(&node->left->lock)) {
          gt_w_nop(w);
        }

        unlock(&node->lock);

        node = next;
      }
    }
    else if (diff > 0) {
      if (!node->right) {
        node->right = route;

        route->parent = node;
        route->left = NULL;
        route->right = NULL;

        unlock(&node->lock);
        unlock(&route->lock);

        return 1;
      }
      else {
        struct ddb_route *next = node->right;

        while (!try_lock(&node->right->lock)) {
          gt_w_nop(w);
        }

        unlock(&node->lock);

        node = next;
      }
    }
    else {
      unlock(&node->lock);
      unlock(&route->lock);
      return 0;
    }

    ++route->level;
  }

  unlock(&node->lock);
  unlock(&route->lock);

  return 1;
}

long ddb_upsert(struct ddb *ddb,
                const void *key,
                unsigned long key_len,
                const void *data,
                unsigned long data_len,
                struct gt_w *w)
{
  long lock_fd;

  while (1) {
    lock_fd = gt_w_openat(w, ddb->dirfd, "write-lock", O_CREAT|O_RDWR|O_EXCL, 0600);
    if (lock_fd >= 0)
      break;
  }

  struct ddb_node new_node;
  compute_hash(new_node.hash, ddb, key, key_len);
  new_node.size = data_len;
  new_node.left = 0;
  new_node.right = 0;
  new_node.key_len = key_len;

  unsigned long new_node_ptr = ddb->meta.file_ptr;
  unsigned long bucket0 = new_node_ptr / ddb->bsize;
  unsigned long bucket1 = (new_node_ptr + 80) / ddb->bsize;
  if (bucket0 != bucket1)
    new_node_ptr = bucket1 * ddb->bsize;

  assert(new_node_ptr >= 4096 + 80);

  unsigned long new_node_real_len = sizeof(struct ddb_node) + key_len;
  new_node.content = new_node_ptr + new_node_real_len;

  assert(new_node.content >= 4096 + 80 + 80);

  // insert data
  char raw_buf[ddb->bsize * 2 - 1];
  unsigned long raw_addr = (unsigned long)raw_buf;
  raw_addr += ddb->bsize - 1;
  raw_addr -= raw_addr % ddb->bsize;
  void *aligned = (void*)raw_addr;

  long r;

  r = _write(ddb, aligned, new_node_ptr + 80, key, key_len, w);
  if (!r)
    goto err;

  if (data_len > 0) {
    r = _write(ddb, aligned, new_node.content, data, data_len, w);
    if (!r)
      goto err;
  }

  while (gt_w_fsync(w, ddb->dbfd) < 0) {
  }

  if (gt_w_write(w, lock_fd, 0, &new_node, 80) != 80) {
    goto err;
  }

  while (gt_w_fsync(w, lock_fd) < 0) {
  }

  unsigned long new_file_ptr = new_node.content + new_node.size;
  
  struct ddb_node node;
  unsigned long ptr = ddb->meta.root_ptr;
  unsigned int depth = 0;
  struct ddb_route *route = _find_route(ddb, new_node.hash, w);
  struct ddb_route *upserted = NULL;

  if (route) {
    ptr = route->addr;
    depth = route->level;

    if (memcmp(route->id, new_node.hash, 32) == 0) {
      upserted = route;
    }

    unlock(&route->lock);
  }

  while (1) {
    assert(ptr >= 4096);

    r = _read(ddb, aligned, ptr, &node, 80, w);
    if (!r)
      goto err;

    if (upserted) {
      while (!try_lock(&upserted->lock)) {
        gt_w_nop(w);
      }
      upserted->addr = new_node_ptr;
      unlock(&upserted->lock);
    }

    if (route) {
      if (memcmp(route->id, node.hash, 32) != 0) {
        route = NULL;
      }
    }

    if (depth++ < 17 && !route) {
      while (!try_lock(&ddb->map_lock)) {
        gt_w_nop(w);
      }

      struct ddb_route *new_route = ddb->map + ddb->route_pos++;

      memcpy(new_route->id, node.hash, 32);
      new_route->addr = ptr;
      new_route->lock = 0;

      if (!_append_route(ddb, new_route, w))
        --ddb->route_pos;

      unlock(&ddb->map_lock);
    }

    route = NULL;


    assert(node.parent || node.content == 4096 + 80);

    int diff = memcmp(new_node.hash, node.hash, 32);
    if (diff == 0) {
      assert(node.content != 4096 + 80);

      new_node.left = node.left;
      new_node.right = node.right;
      new_node.parent = node.parent;

      r = _write(ddb, aligned, new_node_ptr, &new_node, 80, w);
      if (!r)
        goto err;

      struct ddb_node child;

      if (new_node.left) {
        r = _read(ddb, aligned, new_node.left, &child, 80, w);
        if (!r)
          goto err;

        assert(child.parent == ptr);

        child.parent = new_node_ptr;
        r = _write(ddb, aligned, new_node.left, &child, 80, w);
        if (!r)
          goto err;
      }

      if (new_node.right) {
        r = _read(ddb, aligned, new_node.right, &child, 80, w);
        if (!r)
          goto err;

        assert(child.parent == ptr);

        child.parent = new_node_ptr;
        r = _write(ddb, aligned, new_node.right, &child, 80, w);
        if (!r)
          goto err;
      }

      struct ddb_node parent;
      r = _read(ddb, aligned, new_node.parent, &parent, 80, w);
      if (!r)
        goto err;

      if (parent.right == ptr) {
        parent.right = new_node_ptr;
      }
      else {
        assert(parent.left == ptr);
        parent.left = new_node_ptr;
      }

      r = _write(ddb, aligned, new_node.parent, &parent, 80, w);
      if (!r)
        goto err;

      break;
    }

    if (diff < 0) {
      // go left
      if (node.left == 0) {
        new_node.parent = ptr;
        node.left = new_node_ptr;

        r = _write(ddb, aligned, new_node_ptr, &new_node, 80, w);
        if (!r)
          goto err;

        r = _write(ddb, aligned, ptr, &node, 80, w);
        if (!r)
          goto err;

        break;
      }
      else {
        ptr = node.left;
      }
    }

    else {
      // go right
      if (node.right == 0) {
        new_node.parent = ptr;
        node.right = new_node_ptr;

        r = _write(ddb, aligned, new_node_ptr, &new_node, 80, w);
        if (!r)
          goto err;

        r = _write(ddb, aligned, ptr, &node, 80, w);
        if (!r)
          goto err;

        break;
      }
      else {
        ptr = node.right;
      }
    }

    ++depth;
  }

  if (route && memcmp(route->id, node.hash, 32) != 0) {
    route = NULL;
  }

  if (depth++ < 17) {
    while (!try_lock(&ddb->map_lock)) {
      gt_w_nop(w);
    }

    struct ddb_route *new_route = ddb->map + ddb->route_pos++;

    memcpy(new_route->id, new_node.hash, 32);
    new_route->addr = new_node_ptr;
    new_route->lock = 0;

    if (!_append_route(ddb, new_route, w))
      --ddb->route_pos;

    unlock(&ddb->map_lock);
  }

  ddb->meta.file_ptr = new_file_ptr;

  r = _write(ddb, aligned, 0, &ddb->meta, 32, w);
  if (!r)
    goto err;

  while (gt_w_fsync(w, ddb->dbfd) < 0) {
  }

  while (gt_w_close(w, lock_fd) < 0) {
  }

  while (gt_w_unlinkat(w, ddb->dirfd, "write-lock", 0) < 0) {
  }

  return 1;
  
err:
  while (gt_w_close(w, lock_fd) < 0) {
  }

  while (gt_w_unlinkat(w, ddb->dirfd, "write-lock", 0) < 0) {
  }

  return 0;
}


long ddb_delete(struct ddb *ddb,
                const void *key,
                unsigned long key_len,
                struct gt_w *w)
{
  return ddb_upsert(ddb, key, key_len, NULL, 0, w);
}

long ddb_find(struct ddb_result *res,
              struct ddb *ddb,
              const void *key,
              unsigned long key_len,
              struct gt_w *w)
{
  unsigned char hash[32];
  compute_hash(hash, ddb, key, key_len);

  unsigned long ptr = ddb->meta.root_ptr;
  struct ddb_node node;
  long r;

  char raw_buf[ddb->bsize * 2 - 1];
  unsigned long raw_addr = (unsigned long)raw_buf;
  raw_addr += ddb->bsize - 1;
  raw_addr -= raw_addr % ddb->bsize;
  void *aligned = (void*)raw_addr;
  int depth = 0;
  
  struct ddb_route *route = _find_route(ddb, hash, w);

  if (route) {
    //memcpy(node.hash, route->id, 32);

    assert(route->addr >= 4096);
    //node.content = route->addr + 80;
    //node.parent = route->parent ? route->parent->addr : 0;
    //node.left = route->left ? route->left->addr : 0;
    //node.right = route->right ? route->right->addr : 0;

    depth = route->level;
    ptr = route->addr;

    unlock(&route->lock);
  }

  while (ptr) {
    r = _read(ddb, aligned, ptr, &node, 80, w);
    if (!r)
      goto err;

    if (depth++ < 17 && !route) {
      while (!try_lock(&ddb->map_lock)) {
        gt_w_nop(w);
      }
      struct ddb_route *new_route = ddb->map + ddb->route_pos++;

      memcpy(new_route->id, node.hash, 32);
      new_route->addr = ptr;
      new_route->lock = 0;

      if (!_append_route(ddb, new_route, w))
        --ddb->route_pos;

      unlock(&ddb->map_lock);
    }

    route = NULL;

    int diff = memcmp(hash, node.hash, 32);
    if (diff == 0) {
      res->start = node.content;
      res->pos = 0;
      res->size = node.size;
      res->ddb = ddb;

      if (res->size == 0)
        return 0;

      return 1;
    }

    if (diff < 0) {
      ptr = node.left;
    }
    else {
      ptr = node.right;
    }
  }

err:
  return 0;
}

long ddb_read(struct ddb_result *res,
              void *dest,
              unsigned long len,
              struct gt_w *w)
{
  char raw_buf[res->ddb->bsize * 2 - 1];
  unsigned long raw_addr = (unsigned long)raw_buf;
  raw_addr += res->ddb->bsize - 1;
  raw_addr -= raw_addr % res->ddb->bsize;

  void *aligned = (void*)raw_addr;
  unsigned long max = res->size - res->pos;
  unsigned long n = len < max ? len : max;

  if (n == 0)
    return 0;

  long r = _read(res->ddb, aligned, res->start + res->pos, dest, n, w);
  if (!r)
    return 0;

  res->pos += n;

  return n;
}

// TODO FIXME
long ddb_restart_after_failure(struct ddb *ddb, struct gt_w *w)
{
  char raw_buf[ddb->bsize * 2 - 1];
  unsigned long raw_addr = (unsigned long)raw_buf;
  raw_addr += ddb->bsize - 1;
  raw_addr -= raw_addr % ddb->bsize;
  void *aligned = (void*)raw_addr;

  // open log
  long lock_fd = gt_w_openat(w, ddb->dirfd, "write-lock", O_RDONLY, 0);
  if (lock_fd < 0) {
    goto err;
  }
  
  struct ddb_node new_node;
  if (gt_w_read(w, lock_fd, 0, &new_node, 80) != 80) {
    goto end;
  }

  unsigned long new_node_ptr = new_node.content
                               - new_node.key_len
                               - 80;
  struct ddb_node node;
  unsigned long ptr = ddb->meta.root_ptr;
  
  while (1) {
    long r = _read(ddb, aligned, ptr, &node, 80, w);
    if (!r)
      goto err1;

    int diff = memcmp(new_node.hash, node.hash, 32);
    if (diff < 0) {
      if (node.left != 0) {
        if (node.left != new_node_ptr) {
          ptr = node.left;
        }
        else {
          // reinsert new node
          node.left = new_node_ptr;
          break;
        }
      }
      else {
        // insert new node
        node.left = new_node_ptr;
        break;
      }
    }
    else {
      if (node.right != 0) {
        if (node.right != new_node_ptr) {
          ptr = node.right;
        }
        else {
          // reinsert new node
          node.right = new_node_ptr;
          break;
        }
      }
      else {
        // insert new node
        node.right = new_node_ptr;
        break;
      }
    }
  }

  long r = _write(ddb, aligned, ptr, &node, 80, w);
  if (!r)
    goto err1;

  r = _write(ddb, aligned, new_node_ptr, &new_node, 80, w);
  if (!r)
    goto err1;

  ddb->meta.file_ptr = new_node.content + new_node.size;

  r = _write(ddb, aligned, 0, &ddb->meta, 32, w);
  if (!r)
    goto err1;

  while (gt_w_fsync(w, ddb->dbfd) < 0) {
  }

end:
  while (gt_w_close(w, lock_fd) < 0) {
  }
  while (gt_w_unlinkat(w, ddb->dirfd, "write-lock", 0) < 0) {
  }

  return 1;

err1:
  while (gt_w_close(w, lock_fd) < 0) {
  }
err:
  return 0;
}


long ddb_iter(struct ddb_iter *iter,
              struct ddb *ddb,
              struct gt_w *w)
{
  iter->ddb = ddb;
  iter->node_ptr = ddb->meta.root_ptr;
  return 1;
}

static unsigned long fix_node_ptr(struct ddb *ddb, unsigned long node_ptr)
{
  unsigned long bucket0 = node_ptr / ddb->bsize;
  unsigned long bucket1 = (node_ptr + 80) / ddb->bsize;
  if (bucket0 != bucket1)
    node_ptr = bucket1 * ddb->bsize;

  return node_ptr;
}

long ddb_iter_next(struct ddb_result *res,
                   struct ddb_iter *iter,
                   struct gt_w *w)
{
  struct ddb *ddb = iter->ddb;
  char raw_buf[ddb->bsize * 2 - 1];
  unsigned long raw_addr = (unsigned long)raw_buf;
  raw_addr += ddb->bsize - 1;
  raw_addr -= raw_addr % ddb->bsize;
  void *aligned = (void*)raw_addr;

  int skipping = 1;
  unsigned long node_ptr = iter->node_ptr;

  while (1) {
    assert(node_ptr <= ddb->meta.file_ptr);

    if (node_ptr == ddb->meta.file_ptr)
      return 0;

    // get the node
    struct ddb_node node;
    long r = _read(ddb, aligned, node_ptr, &node, 80, w);
    if (!r)
      return 0;

    assert(node.content);

    if (skipping || node.size == 0) {
      node_ptr = node.content + node.size;
      node_ptr = fix_node_ptr(ddb, node_ptr);
      skipping = 0;
      continue;
    }

    // if the node was deleted, the parent won't show it
    if (node.parent) {
      assert(node_ptr >= 4096 + 80);

      struct ddb_node parent_node;
      r = _read(ddb, aligned, node.parent, &parent_node, 80, w);
      if (!r)
        return 0;

      if (parent_node.left == node_ptr || parent_node.right == node_ptr) {
        // it wasn't deleted
        // just return it
        node_ptr = fix_node_ptr(ddb, node_ptr);
        iter->node_ptr = node_ptr;
        res->start = node.content;
        res->pos = 0;
        res->size = node.size;
        res->ddb = ddb;
        return 1;
      }

      // this means the node was deleted
      node_ptr = node.content + node.size;
      node_ptr = fix_node_ptr(ddb, node_ptr);
    }
  }
}
