#include "types.h"
#include "stat.h"
#include "user.h"

int
main(int argc, char *argv[])
{
    int e_flag = 0;
    if(argc > 1 && strcmp(argv[1], "-e") == 0)
        e_flag = 1;

    char state[16];
    char namebuf[16];
    int pid = getpid();

    if(!e_flag){
    // Set the name of this process to "ps"
    fill_proc_name(pid, "ps");

    printf(1, "PID\tNAME\tSTATE\tSYS\tINT\n");

    if(get_proc_state(pid, state, sizeof(state)) == 0){
        printf(1, "%d\tps\tUNKNOWN\t%d\t%d\n",
               pid,
               get_num_syscall(pid),
               get_num_timer_interrupts(pid));
        exit();
    }

    if(get_proc_name(pid, namebuf, sizeof(namebuf)) == 0){
        strcpy(namebuf, "ps");
    }

    printf(1, "%d\t%s\t%s\t%d\t%d\n",
           pid,
           namebuf,
           state,
           get_num_syscall(pid),
           get_num_timer_interrupts(pid));

    exit();
}


    // ps -e
    printf(1, "PID\tSTATE\tSYS\tINT\n");

    for(int p = 1; p <= 64; p++){
        char st[16];

        // Check validity — state fetch returns 1 on success
        if(get_proc_state(p, st, sizeof(st)) == 1){
            printf(1, "%d\t%s\t%d\t%d\n",
                   p,
                   st,
                   get_num_syscall(p),
                   get_num_timer_interrupts(p));
        }
    }

    exit();
}
