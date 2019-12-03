#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>

#include "apfs.h"
#include "util.h"


#define MAX_DESCRIPTORS 32

void get_descriptors(char const *path, nx_superblock_t **descriptors)
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

    xfree(sb_p);
    fclose(fp);
}


void get_backup(char const *path, nx_superblock_t *backup)
{
    int i;
    int i_max_o_xid = INT_MIN;
    FILE *fp;
    nx_superblock_t *sb_p;
    nx_superblock_t **descriptors;
    xid_t max_o_xid = 0;

    fp = fopen(path, "rb");
    if (!fp) {
        fprintf(stderr, "Failed to open file\n");
        exit(1);
    }
    sb_p = (nx_superblock_t *)xmalloc(sizeof(nx_superblock_t));
    fread(sb_p, sizeof(nx_superblock_t), 1, fp);
    fclose(fp);

    descriptors = xmalloc(sizeof(nx_superblock_t *) * sb_p->nx_xp_desc_blocks);
    for (i = 0; i < sb_p->nx_xp_desc_blocks; i++)
        descriptors[i] = (nx_superblock_t *)xmalloc(sizeof(nx_superblock_t));

    get_descriptors(path, descriptors);

    // find largest o_xid which is the backup descriptor of container superblock
    for (i = 0; i < sb_p->nx_xp_desc_blocks; i++) {
        if ((descriptors[i]->nx_o.o_type & 0xff) != OBJECT_TYPE_NX_SUPERBLOCK)
            continue;
        if (max_o_xid < descriptors[i]->nx_o.o_xid) {
            max_o_xid = descriptors[i]->nx_o.o_xid;
            i_max_o_xid = i;
        }
    }

    if (i == INT_MIN) {
        fprintf(stderr, "Backup not found\n");
    }

    // copy backup superblock to given pointer
    memcpy(backup, descriptors[i_max_o_xid], sizeof(nx_superblock_t));

    for (i = 0; i < sb_p->nx_xp_desc_blocks; i++)
        xfree(descriptors[i]);
    xfree(descriptors);
}
