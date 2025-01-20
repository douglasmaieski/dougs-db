/*
  Written by Douglas Maieski - https://github.com/douglasmaieski/
*/


#include "thread.h"

unsigned long long load_qword(const void *ptr)
{
  unsigned long long qword;
  __asm__
  (
    "mov (%1),%0"
    : "=r" (qword)
    : "r" (ptr)
  );
  return qword;
}

unsigned int load_dword(const void *ptr)
{
  unsigned int dword;
  __asm__
  (
    "movl (%1),%0"
    : "=r" (dword)
    : "r" (ptr)
  );
  return dword;
}

void spin_lock(int *lock)
{
  __asm__ goto
  (
    "mov $1,%%rcx\n"
    "xor %%rax,%%rax\n"
    "lock cmpxchg %%ecx,(%0)\n"
    "jz %l1"
    :
    : "r" (lock)
    : "%rcx", "%rax", "memory", "cc"
    : end
  );

l0:
  __asm__ goto
  (
    "pause\n"
    "mov $1,%%rcx\n"
    "xor %%rax,%%rax\n"
    "lock cmpxchg %%ecx,(%0)\n"
    "jnz %l1"
    :
    : "r" (lock)
    : "%rcx", "%rax", "memory", "cc"
    : l0
  );

end:
  return;
}

int try_lock(int *lock)
{
  __asm__ goto 
  (
    "mov $1,%%rcx\n"
    "xor %%rax,%%rax\n"
    "lock cmpxchg %%ecx,(%0)\n"
    "jz %l1"
    :
    : "r" (lock)
    : "%rcx", "%rax", "memory", "cc"
    : success
  );

  return 0;

success:
  return 1;
}

void unlock(int *lock)
{
  __asm__
  (
    "movl $0,(%0)"
    :
    : "r" (lock)
    : "memory"
  );
}

void asm_pause(void)
{
  __asm__ volatile
  (
    "pause"
    :
    :
  );
}

void spin_wait_for_0(long long *x)
{
  __asm__ goto
  (
    "cmpq $0,(%0)\n"
    "je %l1"
    :
    : "r" (x)
    : "cc"
    : end
  );
  
spin:
  __asm__ goto
  (
    "pause\n"
    "cmpq $0,(%0)\n"
    "jne %l1"
    :
    : "r" (x)
    : "cc"
    : spin
  );
end:
  return;
}

void locked_inc(long long *x)
{
  __asm__ __volatile__
  (
    "lock incq (%0)"
    :
    : "r" (x)
    : "cc"
  );
}

void locked_dec(long long *x)
{
  __asm__ __volatile__
  (
    "lock decq (%0)"
    :
    : "r" (x)
    : "cc"
  );
}

void locked_sub_dword(int *ptr, int x)
{
  __asm__ __volatile__
  (
    "lock subl %1,(%0)"
    :
    : "r" (ptr), "r" (x)
    : "cc"
  );
}

void locked_add_dword(int *ptr, int x)
{
  __asm__ __volatile__
  (
    "lock addl %1,(%0)"
    :
    : "r" (ptr), "r" (x)
    : "cc"
  );
}
