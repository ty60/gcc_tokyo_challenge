#include <stdio.h>

int strcmp(const char *p1, const char *p2)
{
    const char *s1 = p1;
    const char *s2 = p2;
    unsigned char c1, c2;
    printf("My strcmp\n");

    do {
        c1 = (unsigned char)*s1++;
        c2 = (unsigned char)*s2++;

        if (c1 == '\0')
            return c1 - c2;
    } while(c1 == c2);
    return c1 - c2;
}
