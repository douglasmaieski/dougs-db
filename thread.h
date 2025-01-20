/*
  Written by Douglas Maieski - https://github.com/douglasmaieski/
*/


#ifndef THREAD_H
#define THREAD_H

#define barrier() __asm__ __volatile__ ( "" : : : "memory")

unsigned long long load_qword(const void *ptr);
unsigned int load_dword(const void *ptr);

void spin_lock(int *lock);
int try_lock(int *lock);
void unlock(int *lock);

void asm_pause(void);

void spin_wait_for_0(long long *x);

void locked_inc(long long *x);
void locked_dec(long long *x);

void locked_sub_dword(int *ptr, int x);
void locked_add_dword(int *ptr, int x);

#endif
