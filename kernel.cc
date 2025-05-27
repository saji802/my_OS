#include "kernel.hh"
#include "k-apic.hh"
#include "k-vmiter.hh"
#include <atomic>

// kernel.cc
//
//    This is the kernel.


// INITIAL PHYSICAL MEMORY LAYOUT
//
//  +-------------- Base Memory --------------+
//  v                                         v
// +-----+--------------------+----------------+--------------------+---------/
// |     | Kernel      Kernel |       :    I/O | App 1        App 1 | App 2
// |     | Code + Data  Stack |  ... #include "u-lib.hh" : Memory | Code + Data  Stack | Code ...
// +-----+--------------------+----------------+--------------------+---------/
// 0  0x40000              0x80000 0xA0000 0x100000             0x140000
//                                             ^
//                                             | \___ PROC_SIZE ___/
//                                      PROC_START_ADDR

#define PROC_SIZE 0x40000       // initial state only

proc ptable[NPROC];             // array of process descriptors
                                // Note that `ptable[0]` is never used.
proc* current;                  // pointer to currently executing proc

#define HZ 100                  // timer interrupt frequency (interrupts/sec)
static std::atomic<unsigned long> ticks; // # timer interrupts so far


// Memory state
//    Information about physical page with address `pa` is stored in
//    `pages[pa / PAGESIZE]`. In the handout code, each `pages` entry
//    holds an `refcount` member, which is 0 for free pages.
//    You can change this as you see fit.

pageinfo pages[NPAGES];


[[noreturn]] void schedule();
[[noreturn]] void run(proc* p);
void exception(regstate* regs);
uintptr_t syscall(regstate* regs);
void memshow();
void free_pagetable(x86_64_pagetable *pagetable);


// kernel(command)
//    Initialize the hardware and processes and start running. The `command`
//    string is an optional string passed from the boot loader.

static void process_setup(pid_t pid, const char* program_name);

void kernel(const char* command) {
    // Initialize hardware.
    init_hardware();
    log_printf("Starting WeensyOS\n");

    // Initialize timer interrupt.
    ticks = 1;
    init_timer(HZ);

    // Clear screen.
    console_clear();

    // (re-)Initialize the kernel page table.
    for (vmiter it(kernel_pagetable); it.va() < MEMSIZE_PHYSICAL; it += PAGESIZE) {
        if (it.va() != 0) {
            if (it.va()<PROC_START_ADDR && it.va()!=CONSOLE_ADDR){
                 it.map(it.va(), PTE_P | PTE_W);
            }else{
                 it.map(it.va(), PTE_P | PTE_W | PTE_U);
            }
        } else {
            // nullptr is inaccessible even to the kernel
            it.map(it.va(), 0);
        }
    }

    // Set up process descriptors.
    for (pid_t i = 0; i < NPROC; i++) {
        ptable[i].pid = i;
        ptable[i].state = P_FREE;
    }
    if (command && program_loader(command).present()) {
        process_setup(1, command);
    } else {
        process_setup(1, "allocator");
        process_setup(2, "allocator2");
        process_setup(3, "allocator3");
        process_setup(4, "allocator4");
    }
    // Switch to the first process using run().
    run(&ptable[1]);
}


// kalloc(sz)
//    Kernel memory allocator. Allocates `sz` contiguous bytes and
//    returns a pointer to the allocated memory (the physical address of
//    the newly allocated memory), or `nullptr` on failure.
//
//    The returned memory is initialized to 0xCC, which corresponds to
//    the x86 instruction `int3` (this may help you debug). You can
//    reset it to something more useful.
//
//    On WeensyOS, `kalloc` is a page-based allocator: if `sz > PAGESIZE`
//    the allocation fails; if `sz < PAGESIZE` it allocates a whole page
//    anyway.
//
//    The stencil code returns the next allocatable free page it can find,
//    but it never reuses pages or supports freeing memory (you'll have to
//    change this at some point).

static uintptr_t next_alloc_pa;

void* kalloc(size_t sz) {
    if (sz > PAGESIZE) {
        return nullptr;
    }
    uintptr_t alloc_pa = 0;
    while (alloc_pa < MEMSIZE_PHYSICAL) {
        uintptr_t pa = alloc_pa;
        alloc_pa += PAGESIZE;
        if (allocatable_physical_address(pa)
            && !pages[pa / PAGESIZE].used() && pa!=0) {
            pages[pa / PAGESIZE].refcount += 1;
            memset((void*) pa, 0xCC, PAGESIZE);
            return (void*) pa;
        }
    }
    return nullptr;
}


// kfree(kptr)
//    Frees `kptr`, which must have been previously returned by `kalloc`.
//    If `kptr == nullptr` does nothing.

void kfree(void* kptr) {
    // Placeholder code below - you will have to implement `kfree`!
    if (kptr == nullptr) {
        return;
    }
    uintptr_t pa = (uintptr_t)kptr;
    if (pa % PAGESIZE != 0 || pa >= MEMSIZE_PHYSICAL || !pages[pa / PAGESIZE].refcount) {
        panic("kfree: invalid pointer %p\n", kptr); 
        return;
    }
    uintptr_t page_idx = pa / PAGESIZE;
    if (--pages[page_idx].refcount == 0) {
        memset(kptr, 0, PAGESIZE); 
    }
}


// process_setup(pid, program_name)
//    Loads application program `program_name` as process number `pid`.
//    This loads the application's code and data into memory, sets its
//    %rip and %rsp, gives it a stack page, and marks it as runnable.

void process_setup(pid_t pid, const char* program_name) {
    init_process(&ptable[pid], 0);
    // Initialize this process's page table. Notice how we are currently
    // sharing the kernel's page table.
    ptable[pid].pagetable = (x86_64_pagetable*) kalloc(PAGESIZE);
    memset(ptable[pid].pagetable, 0, PAGESIZE);
    // Initialize `program_loader`.
    // The `program_loader` is an iterator that visits segments of executables.
    // Map all kernel pages
    for (vmiter it(kernel_pagetable, 0); it.va() < MEMSIZE_VIRTUAL; it += PAGESIZE) {
    if (!it.present()) {
        continue;
    }

    if (it.va() < PROC_START_ADDR || it.va() == CONSOLE_ADDR) {
        uintptr_t pa = it.pa();
        int flag = it.perm(); // Preserve the original permissions
        
        // Only add PTE_U for CONSOLE_ADDR
        if (it.va() == CONSOLE_ADDR) {
            flag |= PTE_U;
        }
        
        int r = vmiter(ptable[pid].pagetable, it.va()).try_map(pa, flag);
        if (r != 0) {
            log_printf("Failed to map virtual address %p for process %d\n", it.va(), pid);
        }
    }
}
    program_loader loader(program_name);
    // Using the loader, we're going to start loading segments of the program binary into memory
    // (recall that an executable has code/text segment, data segment, etc).

    // First, for each segment of the program, we allocate page(s) of memory.
    for (loader.reset(); loader.present(); ++loader) {
        for (uintptr_t va = round_down(loader.va(), PAGESIZE);
            va < loader.va() + loader.size();
            va += PAGESIZE) {
            // `a` is the virtual address of the current segment's page.
            void* phys_page = kalloc(PAGESIZE);
            uintptr_t pa = (uintptr_t)phys_page;
            memset(phys_page, 0, PAGESIZE);
            uintptr_t page_idx = pa / PAGESIZE;
            
            int perms = PTE_P | (PTE_W * loader.writable())| PTE_U; 
            int r = vmiter(ptable[pid].pagetable, va).try_map(pa, perms);
            if (r != 0) {
                log_printf("Failed to map virtual address %p for process %d\n", va, pid);
            }
            // Read the description on the `pages` array if you're confused about what it is.
            // Here, we're directly getting the page that has the same physical address as the
            // virtual address `a`, and claiming that page by incrementing its reference count
            // (you will have to change this later).
        }
    }

    for (loader.reset(); loader.present(); ++loader) {
        uintptr_t start_va = loader.va();
        uintptr_t end_va = start_va + loader.size();
        uintptr_t start_pa = vmiter(ptable[pid].pagetable, start_va).pa();
        
        for (uintptr_t va = start_va; va < end_va; va += PAGESIZE) {
            uintptr_t pa = vmiter(ptable[pid].pagetable, va).pa();
            assert(pa != 0);
            size_t copy_size = min(PAGESIZE, end_va - va);
            memcpy((void*) pa, loader.data() + (va - start_va), copy_size);
        }
    }

    // Set %rip and mark the entry point of the code.
    ptable[pid].regs.reg_rip = loader.entry();

    uintptr_t stack_va = MEMSIZE_VIRTUAL-PAGESIZE;
    void* stack_phys = kalloc(PAGESIZE);
    memset(stack_phys, 0, PAGESIZE);
    uintptr_t stack_pa = (uintptr_t)stack_phys;

    uintptr_t stack_page_idx = stack_pa / PAGESIZE;

    int perms = PTE_P | PTE_W | PTE_U;
    int r = vmiter(ptable[pid].pagetable, stack_va).try_map(stack_pa, perms);
    if (r != 0) {
        // Handle mapping failure
        log_printf("Failed to map virtual address %p for process %d\n", stack_va, pid);
    }
    // Set %rsp to the start of the stack.
    ptable[pid].regs.reg_rsp = stack_va+PAGESIZE;

    // Finally, mark the process as runnable.
    ptable[pid].state = P_RUNNABLE;
}



// exception(regs)
//    Exception handler (for interrupts, traps, and faults).
//    You should *not* have to edit this function.
//
//    The register values from exception time are stored in `regs`.
//    The processor responds to an exception by saving application state on
//    the kernel's stack, then jumping to kernel assembly code (see
//    k-exception.S). That code saves more registers on the kernel's stack,
//    then calls exception(). This way, the process can be resumed right where
//    it left off before the exception. The pushed registers are popped and
//    restored before returning to the process (see k-exception.S).
//
//    Note that hardware interrupts are disabled when the kernel is running.

void exception(regstate* regs) {
    // Copy the saved registers into the `current` process descriptor.
    current->regs = *regs;
    regs = &current->regs;

    // It can be useful to log events using `log_printf`.
    // Events logged this way are stored in the host's `log.txt` file.
    /* log_printf("proc %d: exception %d at rip %p\n",
                current->pid, regs->reg_intno, regs->reg_rip); */

    // Show the current cursor location and memory state (unless this is a kernel fault).
    console_show_cursor(cursorpos);
    if (regs->reg_intno != INT_PF || (regs->reg_errcode & PFERR_USER)) {
        memshow();
    }

    // If Control-C was typed, exit the virtual machine.
    check_keyboard();


    // Actually handle the exception.
    switch (regs->reg_intno) {

    case INT_IRQ + IRQ_TIMER:
        ++ticks;
        lapicstate::get().ack();
        schedule();
        break;                  /* will not be reached */

    case INT_PF: {
        // Analyze faulting address and access type.
        uintptr_t addr = rdcr2();
        const char* operation = regs->reg_errcode & PFERR_WRITE
                ? "write" : "read";
        const char* problem = regs->reg_errcode & PFERR_PRESENT
                ? "protection problem" : "missing page";

        if (!(regs->reg_errcode & PFERR_USER)) {
            panic("Kernel page fault for %p (%s %s, rip=%p)!\n",
                  addr, operation, problem, regs->reg_rip);
        }
        console_printf(CPOS(24, 0), 0x0C00,
                       "Process %d page fault for %p (%s %s, rip=%p)!\n",
                       current->pid, addr, operation, problem, regs->reg_rip);
        current->state = P_BROKEN;
        break;
    }

    default:
        panic("Unexpected exception %d!\n", regs->reg_intno);

    }

    // Return to the current process (or run something else).
    if (current->state == P_RUNNABLE) {
        run(current);
    } else {
        schedule();
    }
}


// syscall(regs)
//    System call handler.
//
//    The register values from system call time are stored in `regs`.
//    The return value, if any, is returned to the user process in `%rax`.
//
//    Note that hardware interrupts are disabled when the kernel is running.

// Headers for helper functions used by syscall.
int syscall_page_alloc(uintptr_t addr);
pid_t syscall_fork();
void syscall_exit();

uintptr_t syscall(regstate* regs) {
    // Copy the saved registers into the `current` process descriptor.
    current->regs = *regs;
    regs = &current->regs;

    // It can be useful to log events using `log_printf`.
    // Events logged this way are stored in the host's `log.txt` file.
    /* log_printf("proc %d: syscall %d at rip %p\n",
                  current->pid, regs->reg_rax, regs->reg_rip); */

    // Show the current cursor location and memory state (unless this is a kernel fault).
    console_show_cursor(cursorpos);
    memshow();

    // If Control-C was typed, exit the virtual machine.
    check_keyboard();

    // Actually handle the exception.
    switch (regs->reg_rax) {

    case SYSCALL_PANIC:
        panic(nullptr); // does not return

    case SYSCALL_GETPID:
        return current->pid;

    case SYSCALL_YIELD:
        current->regs.reg_rax = 0;
        schedule(); // does not return

    case SYSCALL_PAGE_ALLOC:
        return syscall_page_alloc(current->regs.reg_rdi);

    case SYSCALL_FORK:
        return syscall_fork();

    case SYSCALL_EXIT:
        syscall_exit();
        schedule(); // does not return

    default:
        panic("Unexpected system call %ld!\n", regs->reg_rax);

    }

    panic("Should not get here!\n");
}


// syscall_page_alloc(addr)
//    Helper function that handles the SYSCALL_PAGE_ALLOC system call.
//    This function implement the specification for `sys_page_alloc`
//    in `u-lib.hh` (but in the stencil code, it does not - you will
//    have to change this).

int syscall_page_alloc(uintptr_t addr) {
    assert(addr % PAGESIZE == 0);
    void* phys_page = kalloc(PAGESIZE);
    if (!phys_page) {
        log_printf("Out of memory: kalloc returned nullptr\n");
        return -1;
    }
    memset(phys_page, 0, PAGESIZE);
    intptr_t pa = (uintptr_t)phys_page;

    uintptr_t page_idx = pa / PAGESIZE;
            
    int perms = PTE_P | PTE_W | PTE_U; 
    int r = vmiter(current->pagetable, addr).try_map(pa, perms);
    if (r != 0) {
        log_printf("Failed to map virtual address %p for process %d\n", addr, current->pid);
        return -1;
    }
    return 0;
}

// syscall_fork()
//    Handles the SYSCALL_FORK system call. This function
//    implements the specification for `sys_fork` in `u-lib.hh`.
pid_t syscall_fork() {
    
    int index = -1;
    for(int i=1;i<NPROC;i++){
        if(ptable[i].state==P_FREE){
            index = i;
            ptable[index].state = current->state;
            break;  
        }
    }
    if(index==-1){
        log_printf("Out of memory\n");
        return -1;
    }
    ptable[index].pagetable = (x86_64_pagetable*) kalloc(PAGESIZE);
    if (!ptable[index].pagetable) {
        log_printf("Out of memory: kalloc returned nullptr\n");
        ptable[index].state = P_FREE;
        return -1;
    }
    memset(ptable[index].pagetable, 0, PAGESIZE);
    for (vmiter it(current->pagetable, 0); it.va() < MEMSIZE_VIRTUAL; it += PAGESIZE) {
        if (!it.present()) {
            continue; 
        }
        if(it.va()<PROC_START_ADDR){
            uintptr_t pa = it.pa();
            int flag = 0;
            if(it.writable()) flag |= PTE_W;
            if (it.present())  flag |= PTE_P;
            if (it.user()) flag |= PTE_U;
            int r = vmiter(ptable[index].pagetable, it.va()).try_map(pa, flag);
            if (r != 0) {
                ptable[index].state = P_FREE;  
                free_pagetable(ptable[index].pagetable);
                log_printf("Failed to map virtual address %p for process %d\n", it.va(), current->pid);
                return -1;
            }
        }
        else{
            if(it.writable()){
                void* phys_page = kalloc(PAGESIZE);
                if (!phys_page) {
                    log_printf("Out of memory: kalloc returned nullptr\n");
                    ptable[index].state = P_FREE;
                    free_pagetable(ptable[index].pagetable);
                    return -1;
                }
                uintptr_t pa = (uintptr_t)phys_page;
                memset(phys_page, 0, PAGESIZE);
                memcpy(phys_page,(void*) it.pa(),PAGESIZE);
                int r = vmiter(ptable[index].pagetable, it.va()).try_map(pa, PTE_P|PTE_W|PTE_U);
                if (r != 0) {
                    ptable[index].state = P_FREE;
                    free_pagetable(ptable[index].pagetable);
                    log_printf("Failed to map virtual address %p for process %d\n", it.va(), current->pid);
                    return -1;
                }
            }else{
                uintptr_t pa = it.pa();
                pages[pa / PAGESIZE].refcount += 1;
                int r = vmiter(ptable[index].pagetable, it.va()).try_map(pa, PTE_P|PTE_U);
                if (r != 0) {
                    ptable[index].state = P_FREE;
                    free_pagetable(ptable[index].pagetable);
                    log_printf("Failed to map virtual address %p for process %d\n", it.va(), current->pid);
                    return -1;
                }
            }
        }
    }
    ptable[index].state = P_RUNNABLE;
    ptable[index].regs = current->regs;
    ptable[index].regs.reg_rax=0;
    current->regs.reg_rax = ptable[index].pid;
    return ptable[index].pid;
}

// syscall_exit()
//    Handles the SYSCALL_EXIT system call. This function
//    implements the specification for `sys_exit` in `u-lib.hh`.
void syscall_exit() {
    current->state = P_FREE;
    free_pagetable(current->pagetable);
}

// free_pagetable(x86_64_pagetable *pagetable)
//    Helper function that frees the given page table. This means the
//    destination pages as well as the pages for the page table are all freed.
//    Helpful helper function to implement and use for Step 7!
//    (If you modify the arguments/return type, be sure to change the function
//     prototype at the top of the file as well!)
void free_pagetable(x86_64_pagetable *pagetable) {
    for (vmiter it(pagetable, PROC_START_ADDR); it.va() < MEMSIZE_VIRTUAL; it += PAGESIZE) {
        if (it.present()) {
            kfree((void*)it.pa());
        }
    }
    for (ptiter it(pagetable); it.active(); it.next()) {
        kfree(it.kptr());
    }
    kfree(pagetable);
}

// schedule
//    Picks the next process to run and then run it.
//    If there are no runnable processes, spins forever.
//    You should *not* have to edit this function.

void schedule() {
    pid_t pid = current->pid;
    for (unsigned spins = 1; true; ++spins) {
        pid = (pid + 1) % NPROC;
        if (ptable[pid].state == P_RUNNABLE) {
            run(&ptable[pid]);
        }

        // If Control-C was typed, exit the virtual machine.
        check_keyboard();

        // If spinning forever, show the memviewer.
        if (spins % (1 << 12) == 0) {
            memshow();
            log_printf("%u\n", spins);
        }
    }
}


// run(p)
//    Runs process `p`. This involves setting `current = p` and calling
//    `exception_return` to restore its page table and registers.
//    You should *not* have to edit this function.

void run(proc* p) {
    assert(p->state == P_RUNNABLE);
    current = p;

    // Check the process's current pagetable.
    check_pagetable(p->pagetable);

    // This function is defined in k-exception.S. It restores the process's
    // registers then jumps back to user mode.
    exception_return(p);

    // should never get here
    while (true) {
    }
}


// memshow()
//    Draws a picture of memory (physical and virtual) on the CGA console.
//    Switches to a new process's virtual memory map every 0.25 sec.
//    Uses `console_memviewer()`, a function defined in `k-memviewer.cc`.
//    You should *not* have to edit this function.

void memshow() {
    static unsigned last_ticks = 0;
    static int showing = 0;

    // switch to a new process every 0.25 sec
    if (last_ticks == 0 || ticks - last_ticks >= HZ / 2) {
        last_ticks = ticks;
        showing = (showing + 1) % NPROC;
    }

    proc* p = nullptr;
    for (int search = 0; !p && search < NPROC; ++search) {
        if (ptable[showing].state != P_FREE
            && ptable[showing].pagetable) {
            p = &ptable[showing];
        } else {
            showing = (showing + 1) % NPROC;
        }
    }

    extern void console_memviewer(proc* vmp);
    console_memviewer(p);
}
