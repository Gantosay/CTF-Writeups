#include <stdio.h>
#include <unistd.h>

void shell()
{
    system("/bin/sh");
}

void init()
{
    setvbuf(stdout, 0, 2, 0);   // unbuffered stdout
    alarm(60);                  // kill the process after N seconds (anti-hang)
    puts("   __  ___    ______   ___    \n"
         "  /  |/  /__ /_  __/__<  /_ __\n"
         " / /|_/ / _ `// / / __/ /\\ \\ /\n"
         "/_/  /_/\\_,_//_/ /_/ /_//_\\_\\ \n");
}

void vulnerable()
{
    char buf[24];
    read(0, buf, 32);
}

int main()
{
    init();
    vulnerable();
    return 0;
}