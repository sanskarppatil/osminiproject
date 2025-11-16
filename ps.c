#include "types.h"
#include "stat.h"
#include "user.h"

int
main(int argc, char *argv[])
{
    int e_flag = 0;

    if(argc > 1 && strcmp(argv[1], "-e") == 0)
        e_flag = 1;

    if(!e_flag){
        int pid = getpid();

        // set name to "ps"
        set_proc_name(pid, "ps");

        printf(1, "PID\tNAME\tSTATE\tSYS\tINT\n");

        printf(1, "%d\tps\t%s\t%d\t%d\n",
            pid,
            get_proc_state(pid),           // prints RUNNING/SLEEPING/ZOMBIE
            get_num_syscalls(pid),
            get_num_timer_interrupts(pid)
        );

        exit();
    }

    // ps -e
    printf(1, "PID\tSTATE\tSYS\tINT\n");

    for(int pid = 1; pid <= 64; pid++){
        int sysc = get_num_syscalls(pid);
        int tinc = get_num_timer_interrupts(pid);

        if(sysc >= 0){ // valid process
            printf(1, "%d\t%s\t%d\t%d\n",
                pid,
                get_proc_state(pid),
                sysc,
                tinc
            );
        }
    }

    exit();
}
