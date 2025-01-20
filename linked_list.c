/*
  Written by Douglas Maieski - https://github.com/douglasmaieski/
*/


#include "linked_list.h"
#include <stdlib.h>

void list_init(List* list)
{
  list->head = NULL;
  list->back = NULL;
  list->size = 0;
}

void list_push_back(List* list, ListNode* node)
{
  list->size += 1;
  
  if(list->back){
    node->prev = list->back;
    node->next = NULL;
    list->back->next = node;
    list->back = node;
  }
  
  else {
    list->head = list->back = node;
    node->prev = node->next = NULL;
  }
}

void list_push_head(List* list, ListNode* node)
{
  list->size += 1;
  
  if(list->head){
    node->prev = NULL;
    node->next = list->head;
    list->head->prev = node;
    list->head = node;
  }
  
  else {
    list->head = list->back = node;
    node->prev = node->next = NULL;
  }
}

void list_insert_before(List* list, ListNode* node, ListNode* new_node)
{
  list->size += 1;
  
  if(node == list->head)
    list->head = new_node;
  
  else
    node->prev->next = new_node;
  
  new_node->prev = node->prev;
  new_node->next = node;
  node->prev = new_node;
}

void list_insert_after(List* list, ListNode* node, ListNode* new_node)
{
  list->size += 1;
  
  if(node == list->back)
    list->back = new_node;
  
  else
    node->next->prev = new_node;
  
  new_node->prev = node;
  new_node->next = node->next;
  node->next = new_node;
}

void list_remove(List* list, ListNode* node)
{
  list->size -= 1;

  if(list->head == node)
    list->head = node->next;
  
  if(list->back == node)
    list->back = node->prev;

  if(node->prev)
    node->prev->next = node->next;

  if(node->next)
    node->next->prev = node->prev;
}

void list_iterate(List* list, void(*cb)(List*, ListNode*))
{
  ListNode* next;
  for(ListNode* ite = list->head; ite; ite = next){
    // what if cb calls list_remove() ?
    next = ite->next;
    cb(list, ite);
  }
}
