/*
  Written by Douglas Maieski - https://github.com/douglasmaieski/
*/


#ifndef LINKED_LIST_H
#define LINKED_LIST_H

#include <stddef.h> // size_t

typedef struct list {
  struct list_node* head;
  struct list_node* back;
  size_t size;
} List;

typedef struct list_node {
  struct list_node* prev;
  struct list_node* next;
} ListNode;

void list_init(List* list);
void list_push_back(List* list, ListNode* node);
void list_push_head(List* list, ListNode* node);
void list_insert_before(List* list, ListNode* node, ListNode* new_node);
void list_insert_after(List* list, ListNode* node, ListNode* new_node);
void list_remove(List* list, ListNode* node);

/* The only list modification allowed is for a node to remove itself */
void list_iterate(List* list, void(*cb)(List*, ListNode*));

#endif
