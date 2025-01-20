/*
  Written by Douglas Maieski - https://github.com/douglasmaieski/
*/

#define MEMBER_TO_PARENT(parent_type, member_ptr, member_name) \
  ((parent_type*)((char*)member_ptr - offsetof(parent_type, member_name)))
