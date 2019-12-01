#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <limits.h>

#include "apfs.h"
#include "util.h"


#define MAX_BACKUP 16


/*
 * 1. Open `challenge.raw`.
 * 2. Read volume superblock.
 * 3. Read `nx_xp_desc_block`, the first block starting from `nx_xp_desc_base`.
 * 4. Check object type and skip if the type is `OBJECT_TYPE_CHECKPOINT_MAP`.
 * 5. Find `nx_superblock_t` which the largest `xid`.
 */


int main(void)
{
    FILE *fp = fopen("../sample.raw", "r");
    if (!fp) {
        fprintf(stderr, "Failed to open file\n");
        exit(1);
    }

    nx_superblock_t *sb_p = (nx_superblock_t *)xmalloc(sizeof(nx_superblock_t));
    fread(sb_p, sizeof(nx_superblock_t), 1, fp);

    nx_superblock_t *descriptors[MAX_BACKUP] = {};
    obj_phys_t *hdr = (obj_phys_t *)xmalloc(sizeof(obj_phys_t));
    int i;
    for (i = 0; i < sb_p->nx_xp_desc_blocks; i++) {
        fseek(fp, (sb_p->nx_xp_desc_base + i) * sb_p->nx_block_size, SEEK_SET);

        fread(hdr, sizeof(obj_phys_t), 1, fp);

        fseek(fp, (sb_p->nx_xp_desc_base + i) * sb_p->nx_block_size, SEEK_SET);
        if ((hdr->o_type & 0xffff) == OBJECT_TYPE_NX_SUPERBLOCK) {
            descriptors[i] = xmalloc(sizeof(nx_superblock_t));
            fread(descriptors[i], sizeof(nx_superblock_t), 1, fp);
        } else if ((hdr->o_type & 0xffff) == OBJECT_TYPE_CHECKPOINT_MAP) {
            descriptors[i] = xmalloc(sizeof(checkpoint_map_phys_t));
            fread(descriptors[i], sizeof(checkpoint_map_phys_t), 1, fp);
        } else {
            fprintf(stderr, "Unknown type\n");
            exit(1);
        }
    }
    xfree(hdr);

    int i_max_o_xid = INT_MIN;
    xid_t max_o_xid = 0;
    for (i = 0; i < sb_p->nx_xp_desc_blocks; i++) {
        if ((descriptors[i]->nx_o.o_type & 0xff) != OBJECT_TYPE_NX_SUPERBLOCK)
            continue;
        if (max_o_xid < descriptors[i]->nx_o.o_xid)
            i_max_o_xid = i;
    }

    hexdump(descriptors[i_max_o_xid], sizeof(nx_superblock_t));

    for (i = 0; i < sb_p->nx_xp_desc_blocks; i++) {
        xfree(descriptors[i]);
    }
    xfree(sb_p);
    return 0;
}
