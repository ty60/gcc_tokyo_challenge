#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>

#include "apfs.h"
#include "util.h"


#define MAX_BACKUPS 32


/*
 * 1. Open `challenge.raw`.
 * 2. Read volume superblock.
 * 3. Read `nx_xp_desc_block`, the first block starting from `nx_xp_desc_base`.
 * 4. Check object type and skip if the type is `OBJECT_TYPE_CHECKPOINT_MAP`.
 * 5. Find `nx_superblock_t` which the largest `xid`.
 */


int main(void)
{
    int i;
    xid_t target_xid = 0x3c;
    char *path = "../challenge.raw";
    char *output_path = "../revert_old.raw";
    nx_superblock_t *backup;
    nx_superblock_t *break_blocks[16];
    xid_t break_xids[] = { 0x3e, 0x3d };

    backup = xmalloc(sizeof(nx_superblock_t));
    get_backup(path, backup, target_xid, SPEC_XID);

    for (i = 0; i < sizeof(break_xids) / sizeof(xid_t); i++) {
        break_blocks[i] = xmalloc(sizeof(nx_superblock_t));
        get_backup(path, break_blocks[i], break_xids[i], SPEC_XID);
    }

    FILE *broken_fp = fopen(path, "rb");
    FILE *fixed_fp = fopen(output_path, "wb");

    // Copy original apfs at path to output_path
    int ch;
    while ((ch = fgetc(broken_fp)) != EOF)
        fwrite(&ch, 1, 1, fixed_fp);

    // Skip broken superblock part
    fseek(fixed_fp, 0, SEEK_SET);
    fwrite(backup, sizeof(nx_superblock_t), 1, fixed_fp);

    // Overwrite backups stored as descriptors with broken checksump
    for (i = 0; i < sizeof(break_xids) / sizeof(xid_t); i++) {
        uint64_t offset = get_descriptor_offset(path, break_blocks[i]);
        if (offset == 0) {
            fprintf(stderr, "offset for backup not found");
            exit(1);
        }
        // break offset so it will be ignored on mounting
        memset((break_blocks[i]->nx_o.o_cksum), 0xff, 64);
        fseek(fixed_fp, offset, SEEK_SET);
        fwrite(break_blocks[i], sizeof(nx_superblock_t), 1, fixed_fp);
    }

    xfree(backup);
    for (i = 0; i < sizeof(break_xids) / sizeof(xid_t); i++) {
        xfree(break_blocks[i]);
    }

    fclose(broken_fp);
    fclose(fixed_fp);
    return 0;
}
