#include <stdio.h>
#include <unistd.h>

int main(void)
{
    printf("My current pid is %d\n", getpid());

    for (short i = 0; i < 10; ++i)
    {
        puts("[+] Waiting for some action....");
        sleep(60);
    }
    
    return 0;
}