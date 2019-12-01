#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>

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


void get_backup(char const *path, nx_superblock_t *backup)
{
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        fprintf(stderr, "Failed to open file\n");
        exit(1);
    }

    nx_superblock_t *sb_p = (nx_superblock_t *)xmalloc(sizeof(nx_superblock_t));
    fread(sb_p, sizeof(nx_superblock_t), 1, fp);

    // In the given challenge block_size is zeroed out
    if (sb_p->nx_block_size == 0)
        sb_p->nx_block_size = 0x1000;

    nx_superblock_t *descriptors[MAX_BACKUP] = {};
    obj_phys_t *hdr = (obj_phys_t *)xmalloc(sizeof(obj_phys_t));
    int i;
    // load each descriptor block
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
    // find largest o_xid which is the backup descriptor of container superblock
    for (i = 0; i < sb_p->nx_xp_desc_blocks; i++) {
        if ((descriptors[i]->nx_o.o_type & 0xff) != OBJECT_TYPE_NX_SUPERBLOCK)
            continue;
        if (max_o_xid < descriptors[i]->nx_o.o_xid)
            i_max_o_xid = i;
    }

    // copy backup superblock to given pointer
    memcpy(backup, descriptors[i_max_o_xid], sizeof(nx_superblock_t));

    for (i = 0; i < sb_p->nx_xp_desc_blocks; i++) {
        xfree(descriptors[i]);
    }

    xfree(sb_p);
    fclose(fp);
}


int main(void)
{
    char *path = "../challenge.raw";
    char *output_path = "../fixed.raw";

    nx_superblock_t *sb_p = xmalloc(sizeof(nx_superblock_t));
    get_backup(path, sb_p);

    FILE *broken_fp = fopen(path, "rb");
    FILE *fixed_fp = fopen(output_path, "wb");

    // Write copied backup superblock
    fwrite(sb_p, sizeof(nx_superblock_t), 1, fixed_fp);

    // Skip broken superblock part
    fseek(broken_fp, sizeof(nx_superblock_t), SEEK_SET);

    int ch;
    while ((ch = fgetc(broken_fp)) != EOF)
        fwrite(&ch, 1, 1, fixed_fp);

    xfree(sb_p);
    fclose(broken_fp);
    fclose(fixed_fp);
    return 0;
}
