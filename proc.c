#include "types.h"
#include "defs.h"
#include "param.h"
#include "memlayout.h"
#include "mmu.h"
#include "x86.h"
#include "proc.h"
#include "spinlock.h"

struct {
  struct spinlock lock;
  struct proc proc[NPROC];
} ptable;

static struct proc *initproc;

int nextpid = 1;
extern void forkret(void);
extern void trapret(void);

static void wakeup1(void *chan);

void
pinit(void)
{
  initlock(&ptable.lock, "ptable");
}

// Must be called with interrupts disabled
int
cpuid() {
  return mycpu()-cpus;
}

// Must be called with interrupts disabled to avoid the caller being
// rescheduled between reading lapicid and running through the loop.
struct cpu*
mycpu(void)
{
  int apicid, i;
  
  if(readeflags()&FL_IF)
    panic("mycpu called with interrupts enabled\n");
  
  apicid = lapicid();
  // APIC IDs are not guaranteed to be contiguous. Maybe we should have
  // a reverse map, or reserve a register to store &cpus[i].
  for (i = 0; i < ncpu; ++i) {
    if (cpus[i].apicid == apicid)
      return &cpus[i];
  }
  panic("unknown apicid\n");
}

// Disable interrupts so that we are not rescheduled
// while reading proc from the cpu structure
struct proc*
myproc(void) {
  struct cpu *c;
  struct proc *p;
  pushcli();
  c = mycpu();
  p = c->proc;
  popcli();
  return p;
}

//PAGEBREAK: 32
// Look in the process table for an UNUSED proc.
// If found, change state to EMBRYO and initialize
// state required to run in the kernel.
// Otherwise return 0.
static struct proc*
allocproc(void)
{
  struct proc *p;
  char *sp;

  acquire(&ptable.lock);

  for(p = ptable.proc; p < &ptable.proc[NPROC]; p++)
    if(p->state == UNUSED)
      goto found;

  release(&ptable.lock);
  return 0;

found:
  p->state = EMBRYO;
  p->pid = nextpid++;
  p->syscall_count = 0;
  release(&ptable.lock);

  // Allocate kernel stack.
  if((p->kstack = kalloc()) == 0){
    p->state = UNUSED;
    return 0;
  }
  sp = p->kstack + KSTACKSIZE;

  // Leave room for trap frame.
  sp -= sizeof *p->tf;
  p->tf = (struct trapframe*)sp;

  // Set up new context to start executing at forkret,
  // which returns to trapret.
  sp -= 4;
  *(uint*)sp = (uint)trapret;

  sp -= sizeof *p->context;
  p->context = (struct context*)sp;
  memset(p->context, 0, sizeof *p->context);
  p->context->eip = (uint)forkret;

  return p;
}

//PAGEBREAK: 32
// Set up first user process.
void
userinit(void)
{
  struct proc *p;
  extern char _binary_initcode_start[], _binary_initcode_size[];

  p = allocproc();
  
  initproc = p;
  if((p->pgdir = setupkvm()) == 0)
    panic("userinit: out of memory?");
  inituvm(p->pgdir, _binary_initcode_start, (int)_binary_initcode_size);
  p->sz = PGSIZE;
  memset(p->tf, 0, sizeof(*p->tf));
  p->tf->cs = (SEG_UCODE << 3) | DPL_USER;
  p->tf->ds = (SEG_UDATA << 3) | DPL_USER;
  p->tf->es = p->tf->ds;
  p->tf->ss = p->tf->ds;
  p->tf->eflags = FL_IF;
  p->tf->esp = PGSIZE;
  p->tf->eip = 0;  // beginning of initcode.S

  safestrcpy(p->name, "initcode", sizeof(p->name));
  p->cwd = namei("/");

  // this assignment to p->state lets other cores
  // run this process. the acquire forces the above
  // writes to be visible, and the lock is also needed
  // because the assignment might not be atomic.
  acquire(&ptable.lock);

  p->state = RUNNABLE;

  release(&ptable.lock);
}

// Grow current process's memory by n bytes.
// Return 0 on success, -1 on failure.
int
growproc(int n)
{
  uint sz;
  struct proc *curproc = myproc();

  sz = curproc->sz;
  if(n > 0){
    if((sz = allocuvm(curproc->pgdir, sz, sz + n)) == 0)
      return -1;
  } else if(n < 0){
    if((sz = deallocuvm(curproc->pgdir, sz, sz + n)) == 0)
      return -1;
  }
  curproc->sz = sz;
  switchuvm(curproc);
  return 0;
}

// Create a new process copying p as the parent.
// Sets up stack to return as if from system call.
// Caller must set state of returned proc to RUNNABLE.
int
fork(void)
{
  int i, pid;
  struct proc *np;
  struct proc *curproc = myproc();

  // Allocate process.
  if((np = allocproc()) == 0){
    return -1;
  }

  // Copy process state from proc.
  if((np->pgdir = copyuvm(curproc->pgdir, curproc->sz)) == 0){
    kfree(np->kstack);
    np->kstack = 0;
    np->state = UNUSED;
    return -1;
  }
  np->sz = curproc->sz;
  np->parent = curproc;
  *np->tf = *curproc->tf;
  np->saved_eip = np->tf->eip;

// If parent has set a welcome function, override child's EIP
  if(curproc->welcome_fn != 0){
  np->tf->eip = (uint) curproc->welcome_fn;
  }
  // Clear %eax so that fork returns 0 in the child.
  np->tf->eax = 0;

  for(i = 0; i < NOFILE; i++)
    if(curproc->ofile[i])
      np->ofile[i] = filedup(curproc->ofile[i]);
  np->cwd = idup(curproc->cwd);

  safestrcpy(np->name, curproc->name, sizeof(curproc->name));

  pid = np->pid;

  acquire(&ptable.lock);

  np->state = RUNNABLE;

  release(&ptable.lock);

  return pid;
}

// Exit the current process.  Does not return.
// An exited process remains in the zombie state
// until its parent calls wait() to find out it exited.
void
exit(void)
{
  struct proc *curproc = myproc();
  struct proc *p;
  int fd;

  if(curproc == initproc)
    panic("init exiting");

  // Close all open files.
  for(fd = 0; fd < NOFILE; fd++){
    if(curproc->ofile[fd]){
      fileclose(curproc->ofile[fd]);
      curproc->ofile[fd] = 0;
    }
  }

  begin_op();
  iput(curproc->cwd);
  end_op();
  curproc->cwd = 0;

  acquire(&ptable.lock);

  // Parent might be sleeping in wait().
  wakeup1(curproc->parent);

  // Pass abandoned children to init.
  for(p = ptable.proc; p < &ptable.proc[NPROC]; p++){
    if(p->parent == curproc){
      p->parent = initproc;
      if(p->state == ZOMBIE)
        wakeup1(initproc);
    }
  }

  // Jump into the scheduler, never to return.
  curproc->state = ZOMBIE;
  sched();
  panic("zombie exit");
}

// Wait for a child process to exit and return its pid.
// Return -1 if this process has no children.
int
wait(void)
{
  struct proc *p;
  int havekids, pid;
  struct proc *curproc = myproc();
  
  acquire(&ptable.lock);
  for(;;){
    // Scan through table looking for exited children.
    havekids = 0;
    for(p = ptable.proc; p < &ptable.proc[NPROC]; p++){
      if(p->parent != curproc)
        continue;
      havekids = 1;
      if(p->state == ZOMBIE){
        // Found one.
        pid = p->pid;
        kfree(p->kstack);
        p->kstack = 0;
        freevm(p->pgdir);
        p->pid = 0;
        p->parent = 0;
        p->name[0] = 0;
        p->killed = 0;
        p->state = UNUSED;
        release(&ptable.lock);
        return pid;
      }
    }

    // No point waiting if we don't have any children.
    if(!havekids || curproc->killed){
      release(&ptable.lock);
      return -1;
    }

    // Wait for children to exit.  (See wakeup1 call in proc_exit.)
    sleep(curproc, &ptable.lock);  //DOC: wait-sleep
  }
}

//PAGEBREAK: 42
// Per-CPU process scheduler.
// Each CPU calls scheduler() after setting itself up.
// Scheduler never returns.  It loops, doing:
//  - choose a process to run
//  - swtch to start running that process
//  - eventually that process transfers control
//      via swtch back to the scheduler.
void
scheduler(void)
{
  struct proc *p;
  struct cpu *c = mycpu();
  c->proc = 0;
  
  for(;;){
    // Enable interrupts on this processor.
    sti();

    // Loop over process table looking for process to run.
    acquire(&ptable.lock);
    for(p = ptable.proc; p < &ptable.proc[NPROC]; p++){
      if(p->state != RUNNABLE)
        continue;

      // Switch to chosen process.  It is the process's job
      // to release ptable.lock and then reacquire it
      // before jumping back to us.
      c->proc = p;
      switchuvm(p);
      p->state = RUNNING;

      swtch(&(c->scheduler), p->context);
      switchkvm();

      // Process is done running for now.
      // It should have changed its p->state before coming back.
      c->proc = 0;
    }
    release(&ptable.lock);

  }
}

// Enter scheduler.  Must hold only ptable.lock
// and have changed proc->state. Saves and restores
// intena because intena is a property of this
// kernel thread, not this CPU. It should
// be proc->intena and proc->ncli, but that would
// break in the few places where a lock is held but
// there's no process.
void
sched(void)
{
  int intena;
  struct proc *p = myproc();

  if(!holding(&ptable.lock))
    panic("sched ptable.lock");
  if(mycpu()->ncli != 1)
    panic("sched locks");
  if(p->state == RUNNING)
    panic("sched running");
  if(readeflags()&FL_IF)
    panic("sched interruptible");
  intena = mycpu()->intena;
  swtch(&p->context, mycpu()->scheduler);
  mycpu()->intena = intena;
}

// Give up the CPU for one scheduling round.
void
yield(void)
{
  acquire(&ptable.lock);  //DOC: yieldlock
  myproc()->state = RUNNABLE;
  sched();
  release(&ptable.lock);
}

// A fork child's very first scheduling by scheduler()
// will swtch here.  "Return" to user space.
void
forkret(void)
{
  static int first = 1;
  // Still holding ptable.lock from scheduler.
  release(&ptable.lock);

  if (first) {
    // Some initialization functions must be run in the context
    // of a regular process (e.g., they call sleep), and thus cannot
    // be run from main().
    first = 0;
    iinit(ROOTDEV);
    initlog(ROOTDEV);
  }

  // Return to "caller", actually trapret (see allocproc).
}

// Atomically release lock and sleep on chan.
// Reacquires lock when awakened.
void
sleep(void *chan, struct spinlock *lk)
{
  struct proc *p = myproc();
  
  if(p == 0)
    panic("sleep");

  if(lk == 0)
    panic("sleep without lk");

  // Must acquire ptable.lock in order to
  // change p->state and then call sched.
  // Once we hold ptable.lock, we can be
  // guaranteed that we won't miss any wakeup
  // (wakeup runs with ptable.lock locked),
  // so it's okay to release lk.
  if(lk != &ptable.lock){  //DOC: sleeplock0
    acquire(&ptable.lock);  //DOC: sleeplock1
    release(lk);
  }
  // Go to sleep.
  p->chan = chan;
  p->state = SLEEPING;

  sched();

  // Tidy up.
  p->chan = 0;

  // Reacquire original lock.
  if(lk != &ptable.lock){  //DOC: sleeplock2
    release(&ptable.lock);
    acquire(lk);
  }
}

//PAGEBREAK!
// Wake up all processes sleeping on chan.
// The ptable lock must be held.
static void
wakeup1(void *chan)
{
  struct proc *p;

  for(p = ptable.proc; p < &ptable.proc[NPROC]; p++)
    if(p->state == SLEEPING && p->chan == chan)
      p->state = RUNNABLE;
}

// Wake up all processes sleeping on chan.
void
wakeup(void *chan)
{
  acquire(&ptable.lock);
  wakeup1(chan);
  release(&ptable.lock);
}

// Kill the process with the given pid.
// Process won't exit until it returns
// to user space (see trap in trap.c).
int
kill(int pid)
{
  struct proc *p;

  acquire(&ptable.lock);
  for(p = ptable.proc; p < &ptable.proc[NPROC]; p++){
    if(p->pid == pid){
      p->killed = 1;
      // Wake process from sleep if necessary.
      if(p->state == SLEEPING)
        p->state = RUNNABLE;
      release(&ptable.lock);
      return 0;
    }
  }
  release(&ptable.lock);
  return -1;
}

//PAGEBREAK: 36
// Print a process listing to console.  For debugging.
// Runs when user types ^P on console.
// No lock to avoid wedging a stuck machine further.
void
procdump(void)
{
  static char *states[] = {
  [UNUSED]    "unused",
  [EMBRYO]    "embryo",
  [SLEEPING]  "sleep ",
  [RUNNABLE]  "runble",
  [RUNNING]   "run   ",
  [ZOMBIE]    "zombie"
  };
  int i;
  struct proc *p;
  char *state;
  uint pc[10];

  for(p = ptable.proc; p < &ptable.proc[NPROC]; p++){
    if(p->state == UNUSED)
      continue;
    if(p->state >= 0 && p->state < NELEM(states) && states[p->state])
      state = states[p->state];
    else
      state = "???";
    cprintf("%d %s %s", p->pid, state, p->name);
    if(p->state == SLEEPING){
      getcallerpcs((uint*)p->context->ebp+2, pc);
      for(i=0; i<10 && pc[i] != 0; i++)
        cprintf(" %p", pc[i]);
    }
    cprintf("\n");
  }
}
int
getChildren(void)
{
  struct proc *curproc = myproc();
  struct proc *p;
  int count = 0;

  cprintf("Children PID's are:\n");
  acquire(&ptable.lock);
  for(p = ptable.proc; p < &ptable.proc[NPROC]; p++){
    if(p->parent == curproc && p->state != UNUSED){
      cprintf("%d %s\n", p->pid,p->name);
      count++;
    }
  }
  release(&ptable.lock);
  cprintf("No. of Children: %d\n", count);
  return 0;
}
// In kernel/proc.c

int
getSibling(void)
{
  struct proc *curproc = myproc(); // Get the process calling the syscall
  struct proc *p;                  // A process to iterate with
  int count = 0;

  // The 'init' process (pid 1) has no parent, so it has no siblings.
  // We check for curproc->parent to avoid a null pointer.
  if(curproc->parent == 0){
    cprintf("No siblings found.\n");
    return 0;
  }

  cprintf("Sibling PID's are:\n");

  // Acquire the lock to safely read the process table
  acquire(&ptable.lock);

  // Loop through all processes
  for(p = ptable.proc; p < &ptable.proc[NPROC]; p++){

    // A sibling is a process that:
    // 1. Has the same parent as the current process.
    // 2. Is NOT the current process itself.
    // 3. Is currently active (not UNUSED).
    if(p->parent == curproc->parent && p != curproc && p->state != UNUSED){
      cprintf("%d\n", p->pid);
      count++;
    }
  }

  // Release the lock
  release(&ptable.lock);

  cprintf("No. of Siblings: %d\n", count);
  return 0;
}
void
pstree_helper(struct proc *p, int depth)
{
  // 1. Print indentation
  for (int i = 0; i < depth; i++) {
    cprintf(" "); // Print one space per level of depth
  }

  // 2. Print the current process info
  cprintf("%d [%s]\n", p->pid, p->name);

  // 3. Find all children and recurse
  struct proc *child;
  for (child = ptable.proc; child < &ptable.proc[NPROC]; child++) {
    if (child->parent == p && child->state != UNUSED) {
      // 4. Call self for the child, increasing depth
      pstree_helper(child, depth + 1);
    }
  }
}
int
pstree(void){
 struct proc *curproc = myproc();
 acquire(&ptable.lock);
 pstree_helper(curproc,0);
 release(&ptable.lock);
 return 0;
}
int
is_proc_valid(int pid){
 acquire(&ptable.lock);
 struct proc *p;
 int flag = 1;
 int ans = -1;
 for(p = ptable.proc;p<&ptable.proc[NPROC];p++){
  if(p->pid==pid){
	  flag = 0;
   if(p->state==SLEEPING||p->state==RUNNABLE||p->state==RUNNING){
	   ans = 1;
    }
   else{
	   ans = 0;
   }
  }	  
 }
   
  release(&ptable.lock);
  if(flag){
   cprintf("%s\n","Invalid pid given by process");
   return ans;
  }
  return ans;
}


// ... (existing code like allocproc, userinit, scheduler, etc.) ...

//
// ADD THIS NEW FUNCTION
//
// int get_proc_state(int pid, char *buf, int size)
//
// Looks for a process with the given PID.
// If found, copies the process's state string (e.g., "SLEEPING")
// into the user-space buffer 'buf' up to 'size' bytes.
// Returns 1 on success (process found and copied), 0 otherwise.
//
static char *states[] = {
[UNUSED]    "UNUSED",
[EMBRYO]    "EMBRYO",
[SLEEPING]  "SLEEPING",
[RUNNABLE]  "RUNNABLE",
[RUNNING]   "RUNNING",
[ZOMBIE]    "ZOMBIE"
};
int
get_proc_state(int pid, char *buf, int size)
{
  struct proc *p;
  char *state_str;
  int len;
  int found = 0;

  if (size <= 0) {
    return 0; // Invalid buffer size
  }

  acquire(&ptable.lock);

  // Loop through process table
  for(p = ptable.proc; p < &ptable.proc[NPROC]; p++){
    if(p->pid == pid){
      // Found the process
      state_str = states[p->state];
      len = strlen(state_str) + 1; // Get length including null terminator

      // Determine how many bytes to copy
      // We copy at most 'size' bytes
      int bytes_to_copy = (len < size) ? len : size;

      // Safely copy the string from kernel space to the user-space buffer
      if(copyout(myproc()->pgdir, (uint)buf, state_str, bytes_to_copy) < 0) {
        // Failed to copy to user space (e.g., bad pointer)
        found = 0;
      } else {
        // Success!
        found = 1;

        // If we truncated the string, we must ensure the user's
        // buffer is null-terminated for safety.
        if(bytes_to_copy == size) {
          char null_byte = '\0';
          // Write a null to the very last byte of the user buffer
          copyout(myproc()->pgdir, (uint)buf + size - 1, &null_byte, 1);
          // We ignore the return value here, it's a best-effort
        }
      }

      break; // Exit loop once process is found
    }
  }

  release(&ptable.lock);

  return found;
}
int
fill_proc_name(int pid, const char *name)
{
  struct proc *p;
  int found = 0; // 0 = not found, 1 = found

  acquire(&ptable.lock);

  // Loop through process table
  for(p = ptable.proc; p < &ptable.proc[NPROC]; p++){
    if(p->pid == pid){
      // Found the process. Set flag to 1.
      found = 1;

      // Safely copy the string from user-space (name)
      // into the kernel-space buffer (p->proc_name).
      // We use copyin, which is the correct tool for this.
      if(copyout(p->pgdir, (uint)name, p->proc_name, sizeof(p->proc_name)) < 0) {
        // copyin failed (e.g., user passed a bad pointer).
        // We'll just set the name to empty.
        p->proc_name[0] = '\0';
      } else {
        // copyin succeeded, but it might not have copied a
        // null-terminator if the user string was 16 bytes or longer.
        // We MUST force null-termination at the end of our buffer.
        p->proc_name[sizeof(p->proc_name) - 1] = '\0';
      }
      
      break; // Exit loop once process is found
    }
  }

  release(&ptable.lock);
  
  return found;
}
// ... (existing code in proc.c) ...

//
// ADD THIS NEW FUNCTION
//
// int get_proc_name(int pid, char *buf, int size)
//
// Looks for a process with the given PID.
// If found, copies the process's 'proc_name' string
// into the user-space buffer 'buf'.
// Returns 1 on success, 0 otherwise.
//
int
get_proc_name(int pid, char *buf, int size)
{
  struct proc *p;
  char *process_name;
  int len;
  int found = 0;

  if (size <= 0) {
    return 0; // Invalid buffer size
  }

  acquire(&ptable.lock);

  // Loop through process table
  for(p = ptable.proc; p < &ptable.proc[NPROC]; p++){
    if(p->pid == pid){
      // Found the process.
      // We read from the 'proc_name' field you added.
      process_name = p->proc_name;

      // Get length including null terminator
      len = strlen(process_name) + 1;

      // Determine how many bytes to copy
      // We copy at most 'size' bytes
      int bytes_to_copy = (len < size) ? len : size;

      // Safely copy the string from kernel space (process_name)
      // to the user-space buffer (buf).
      //
      // Prototype from your screenshot:
      // int copyout(pde_t *pgdir, uint va, void *p, uint len);
      //
      // myproc()->pgdir = The user process's page directory
      // (uint)buf       = The user-space virtual address (the buffer)
      // process_name    = The kernel-space data source
      // bytes_to_copy   = The number of bytes
      //
      if(copyout(myproc()->pgdir, (uint)buf, process_name, bytes_to_copy) < 0) {
        // Failed to copy to user space (e.g., bad pointer)
        found = 0;
      } else {
        // Success!
        found = 1;

        // If we truncated the string, we must ensure the user's
        // buffer is null-terminated for safety.
        if(bytes_to_copy == size) {
          char null_byte = '\0';
          // Write a null to the very last byte of the user buffer
          copyout(myproc()->pgdir, (uint)buf + size - 1, &null_byte, 1);
          // We ignore the return value here, it's a best-effort
        }
      }

      break; // Exit loop once process is found
    }
  }

  release(&ptable.lock);

  return found;
}
int
get_num_syscall(int pid)
{
  struct proc *p;
  int count = -1; // Default to -1 (error/not found)

  acquire(&ptable.lock);

  // Loop through process table
  for(p = ptable.proc; p < &ptable.proc[NPROC]; p++){
    if(p->pid == pid){
      // Found the process
      count = p->syscall_count;
      break;
    }
  }

  release(&ptable.lock);

  return count; // Returns -1 if pid not found, or p->syscall_count if found
}
int get_num_timer_interrupts(int pid) {
    struct proc *p;

    acquire(&ptable.lock);
    for(p = ptable.proc; p < &ptable.proc[NPROC]; p++){
        if(p->pid == pid){
            int count = p->timer_interrupt_count;  // field in proc struct
            release(&ptable.lock);
            return count;
        }
    }
    release(&ptable.lock);
    return -1;
}