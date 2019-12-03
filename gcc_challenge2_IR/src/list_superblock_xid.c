#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "apfs.h"
#include "util.h"


#define MAX_DESCRIPTORS 32


/*
 * List xids of all the container superblock backups in checkpoint descriptor area.
 */
int main(void)
{
    nx_superblock_t *descriptors[MAX_DESCRIPTORS];
    memset((void *)descriptors, 0, sizeof(descriptors));

    get_descriptors("../fixed.raw", descriptors);
    int i = 0;
    nx_superblock_t *now;
    while ((now = descriptors[i++])) {
        if ((now->nx_o.o_type & OBJECT_TYPE_TEST) != OBJECT_TYPE_NX_SUPERBLOCK)
            continue;

        printf("%lx\n", now->nx_o.o_xid);
    }

    return 0;
}
