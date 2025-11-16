#include "types.h"
#include "x86.h"
#include "defs.h"
#include "date.h"
#include "param.h"
#include "memlayout.h"
#include "mmu.h"
#include "proc.h"

int
sys_fork(void)
{
  return fork();
}

int
sys_exit(void)
{
  exit();
  return 0;  // not reached
}

int
sys_wait(void)
{
  return wait();
}

int
sys_kill(void)
{
  int pid;

  if(argint(0, &pid) < 0)
    return -1;
  return kill(pid);
}

int
sys_getpid(void)
{
  return myproc()->pid;
}

int
sys_sbrk(void)
{
  int addr;
  int n;

  if(argint(0, &n) < 0)
    return -1;
  addr = myproc()->sz;
  if(growproc(n) < 0)
    return -1;
  return addr;
}

int
sys_sleep(void)
{
  int n;
  uint ticks0;

  if(argint(0, &n) < 0)
    return -1;
  acquire(&tickslock);
  ticks0 = ticks;
  while(ticks - ticks0 < n){
    if(myproc()->killed){
      release(&tickslock);
      return -1;
    }
    sleep(&ticks, &tickslock);
  }
  release(&tickslock);
  return 0;
}

// return how many clock tick interrupts have occurred
// since start.
int
sys_uptime(void)
{
  uint xticks;

  acquire(&tickslock);
  xticks = ticks;
  release(&tickslock);
  return xticks;
}
int
sys_hello(void)
{
  cprintf("Hello\n");
  return 0;
}
int
sys_helloYou(void)
{
  char *name; // This will hold the *safe, copied* string

  // Fetch the 0th argument (the string 'name') from the user.
  // argstr() securely copies it from user memory into kernel memory
  // and puts a pointer to the kernel copy in our 'name' variable.
  if(argstr(0, &name) < 0) {
    // If argstr returns -1, the user gave a bad pointer
    return -1;
  }

  // Now 'name' is a safe kernel pointer to the string
  cprintf("Hello, %s\n", name);
  return 0; // 0 means success
}
int sys_getChildren(void){
 return getChildren();
}
int sys_getSibling(void){
 return getSibling();
}
int sys_getname(void){
 struct proc* curproc = myproc();
 cprintf("%s",curproc->name);
 return 0;
}
int sys_pstree(void){
 return pstree();
}
int
sys_welcomeFunction(void)
{
    uint fn;

    // read argument 0 as an integer (the function address)
    if(argint(0, (int*)&fn) < 0)
        return -1;

    myproc()->welcome_fn = (void (*)())fn;
    return 0;
}
int
sys_welcomeDone(void)
{
    struct proc *p = myproc();
    p->tf->eip = p->saved_eip;     // restore original execution point
    return 0;
}
int
sys_is_proc_valid(void){
  int pid;
    // fetch the first argument (argument #0)
    if(argint(0, &pid) < 0)
        return -1;
   return is_proc_valid(pid); 
}

     
int
sys_get_proc_state(void)
{
  int pid;
  char *buf; // This will hold the user-space address
  int size;

  // Fetch the 1st argument (int pid)
  if(argint(0, &pid) < 0)
    return -1; // Error fetching argument

  // Fetch the 2nd argument (char *buf)
  // We use argint to get the pointer (an address, which is an int)
  // and store it in our 'buf' variable.
  if(argint(1, (int*)&buf) < 0)
    return -1; // Error fetching argument

  // Fetch the 3rd argument (int size)
  if(argint(2, &size) < 0)
    return -1; // Error fetching argument

  // Now, call the real implementation with the fetched arguments
  return get_proc_state(pid, buf, size);
}
int
sys_fill_proc_name(void)
{
  int pid;
  char *name; // This will hold the user-space address of the string

  // Fetch the 1st argument (int pid)
  if(argint(0, &pid) < 0)
    return -1; // Error fetching argument

  // Fetch the 2nd argument (char *name)
  // We use argint to get the pointer (an address, which is an int)
  // and store it in our 'name' variable.
  if(argint(1, (int*)&name) < 0)
    return -1; // Error fetching argument

  // Now, call the real implementation with the fetched arguments
  return fill_proc_name(pid, name);
}
// ... (existing sys_... functions in sysproc.c) ...

//
// ADD THIS NEW FUNCTION
//
// This is the system call wrapper for get_proc_name.
// It retrieves the arguments passed from user space.
//
int
sys_get_proc_name(void)
{
  int pid;
  char *buf; // This will hold the user-space address
  int size;

  // Fetch the 1st argument (int pid)
  if(argint(0, &pid) < 0)
    return -1; // Error fetching argument

  // Fetch the 2nd argument (char *buf)
  if(argint(1, (int*)&buf) < 0)
    return -1; // Error fetching argument

  // Fetch the 3rd argument (int size)
  if(argint(2, &size) < 0)
    return -1; // Error fetching argument

  // Now, call the real implementation with the fetched arguments
  return get_proc_name(pid, buf, size);
}
int
sys_get_num_syscall(void)
{
  int pid;

  // Fetch the 1st argument (int pid)
  if(argint(0, &pid) < 0)
    return -1; // Error fetching argument

  // Call the real implementation
  return get_num_syscall(pid);
}
// timer interrupt count syscall
int sys_get_num_timer_interrupts(void) {
    int pid;
    if(argint(0, &pid) < 0)
        return -1;

    return get_num_timer_interrupts(pid);
}
