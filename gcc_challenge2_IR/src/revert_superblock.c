#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>

#include "apfs.h"
#include "util.h"


#define MAX_DESCRIPTORS 32


/*
 * 1. Open `challenge.raw`.
 * 2. Read volume superblock.
 * 3. Read `nx_xp_desc_block`, the first block starting from `nx_xp_desc_base`.
 * 4. Check object type and skip if the type is `OBJECT_TYPE_CHECKPOINT_MAP`.
 * 5. Find `nx_superblock_t` which the largest `xid`.
 */


/*
 * Copy apfs from path to output_path and overwrite the container superblock with backup.
 */
int main(void)
{
    char *path = "../challenge.raw";
    char *output_path = "../fixed.raw";
    uint64_t offset = 0;

    nx_superblock_t *sb_p = xmalloc(sizeof(nx_superblock_t));
    get_backup(path, sb_p, 0, 0);

    offset = get_descriptor_offset(path, sb_p);
    printf("Copy from %lx\n", offset);
    printf("Copy to: %lx\n", 0UL);

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
