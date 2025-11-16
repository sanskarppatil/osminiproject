#include "types.h"
#include "stat.h"
#include "user.h"

int
main(int argc, char *argv[])
{
    if(argc > 1){
        // User gave a string as argument → pass it to syscall
        // argv[1] is the first argument string
        helloYou(argv[1]);
        exit();
    }

    // No arguments → run your default loop
    for(int i = 0; i < 10; i++){
        helloYou("Calling from XV6");
        helloYou("Welcome to XV6");
    }

    exit();
}
