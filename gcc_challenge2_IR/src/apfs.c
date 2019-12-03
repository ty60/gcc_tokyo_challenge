#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>

#include "apfs.h"
#include "util.h"


/*
 * Load descriptors of apfs specified by the path.
 */
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
    // sb_p->nx_xp_desc_base shows the base block of checkpoint descriptor area.
    // load each descriptor block.
    for (i = 0; i < sb_p->nx_xp_desc_blocks; i++) {
        // 
        // Seek to read object header
        fseek(fp, (sb_p->nx_xp_desc_base + i) * sb_p->nx_block_size, SEEK_SET);

        fread(hdr, sizeof(obj_phys_t), 1, fp);

        // Seek again to read entire object (not only the header like above)
        fseek(fp, (sb_p->nx_xp_desc_base + i) * sb_p->nx_block_size, SEEK_SET);
        if ((hdr->o_type & OBJECT_TYPE_TEST) == OBJECT_TYPE_NX_SUPERBLOCK) {
            descriptors[i] = xmalloc(sizeof(nx_superblock_t));
            fread(descriptors[i], sizeof(nx_superblock_t), 1, fp);
        } else if ((hdr->o_type & OBJECT_TYPE_TEST) == OBJECT_TYPE_CHECKPOINT_MAP) {
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


/*
 * Return the offset to the given descriptor in the apfs at path.
 */
uint64_t get_descriptor_offset(const char *path, nx_superblock_t *descriptor)
{
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        fprintf(stderr, "Failed to open file\n");
        exit(1);
    }

    nx_superblock_t *sb_p = (nx_superblock_t *)xmalloc(sizeof(nx_superblock_t));
    fread(sb_p, sizeof(nx_superblock_t), 1, fp);

    if (sb_p->nx_block_size == 0)
        sb_p->nx_block_size = 0x1000;

    obj_phys_t *hdr = (obj_phys_t *)xmalloc(sizeof(obj_phys_t));
    int i;
    // Check each object header if the object is the descriptor that we are looking for
    for (i = 0; i < sb_p->nx_xp_desc_blocks; i++) {
        fseek(fp, (sb_p->nx_xp_desc_base + i) * sb_p->nx_block_size, SEEK_SET);

        fread(hdr, sizeof(obj_phys_t), 1, fp);

        // Return offset when we find the same header
        if (memcmp(descriptor, hdr, sizeof(obj_phys_t)) == 0) {
            return (uint64_t)((sb_p->nx_xp_desc_base + i) * sb_p->nx_block_size);
        }
    }
    // Couldn't find descriptor
    return 0UL;
}


/*
 * Search for backup of container superblock from checkpoint descriptor area.
 * If SPEC_XID is specified in flag it will search for backup with generation target_xid.
 * If SPEC_XID is not specified it will load the most recent backup and target_xid is ignored.
 */
void get_backup(char const *path, nx_superblock_t *backup, xid_t target_xid, int flag)
{
    int i;
    int target_i_xid = INT_MIN;
    FILE *fp;
    nx_superblock_t *sb_p;
    nx_superblock_t **descriptors;
    xid_t backup_xid = 0;

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
        if ((descriptors[i]->nx_o.o_type & OBJECT_TYPE_TEST) != OBJECT_TYPE_NX_SUPERBLOCK)
            continue;

        if ((flag & SPEC_XID) && target_xid == descriptors[i]->nx_o.o_xid) {
            // When SPEC_XID (specify xid) flag is set look for the specified xid
            backup_xid = target_xid;
            target_i_xid = i;
        } else if (!(flag & SPEC_XID) && backup_xid < descriptors[i]->nx_o.o_xid) {
            // When SPEC_XID flag is not set look for the largest xid,
            // which is the latest generation of the backup
            backup_xid = descriptors[i]->nx_o.o_xid;
            target_i_xid = i;
        }
    }

    if (target_i_xid == INT_MIN) {
        fprintf(stderr, "Backup not found\n");
    }

    // copy backup superblock to given pointer
    memcpy(backup, descriptors[target_i_xid], sizeof(nx_superblock_t));

    for (i = 0; i < sb_p->nx_xp_desc_blocks; i++)
        xfree(descriptors[i]);
    xfree(descriptors);
}
