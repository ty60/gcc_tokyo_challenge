#ifndef APFS_H
#define APFS_H

#include <stdint.h>

#define OBJECT_TYPE_NX_SUPERBLOCK 0x00000001
#define OBJECT_TYPE_BTREE 0x00000002
#define OBJECT_TYPE_BTREE_NODE 0x00000003
#define OBJECT_TYPE_SPACEMAN 0x00000005
#define OBJECT_TYPE_SPACEMAN_CAB 0x00000006
#define OBJECT_TYPE_SPACEMAN_CIB 0x00000007
#define OBJECT_TYPE_SPACEMAN_BITMAP 0x00000008
#define OBJECT_TYPE_SPACEMAN_FREE_QUEUE 0x00000009
#define OBJECT_TYPE_EXTENT_LIST_TREE 0x0000000a
#define OBJECT_TYPE_OMAP 0x0000000b
#define OBJECT_TYPE_CHECKPOINT_MAP 0x0000000c
#define OBJECT_TYPE_FS 0x0000000d
#define OBJECT_TYPE_FSTREE 0x0000000e
#define OBJECT_TYPE_BLOCKREFTREE 0x0000000f
#define OBJECT_TYPE_SNAPMETATREE 0x00000010
#define OBJECT_TYPE_NX_REAPER 0x00000011
#define OBJECT_TYPE_NX_REAP_LIST 0x00000012
#define OBJECT_TYPE_OMAP_SNAPSHOT 0x00000013
#define OBJECT_TYPE_EFI_JUMPSTART 0x00000014
#define OBJECT_TYPE_FUSION_MIDDLE_TREE 0x00000015
#define OBJECT_TYPE_NX_FUSION_WBC 0x00000016
#define OBJECT_TYPE_NX_FUSION_WBC_LIST 0x00000017
#define OBJECT_TYPE_ER_STATE 0x00000018
#define OBJECT_TYPE_GBITMAP 0x00000019
#define OBJECT_TYPE_GBITMAP_TREE 0x0000001a
#define OBJECT_TYPE_GBITMAP_BLOCK 0x0000001b
#define OBJECT_TYPE_INVALID 0x00000000
#define OBJECT_TYPE_TEST 0x000000ff
#define OBJECT_TYPE_CONTAINER_KEYBAG 'keys'
#define OBJECT_TYPE_VOLUME_KEYBAG 'recs'

typedef struct nx_superblock nx_superblock_t;
#define NX_MAGIC 'BSXN'
#define NX_MAX_FILE_SYSTEMS 100
#define NX_EPH_INFO_COUNT 4
#define NX_EPH_MIN_BLOCK_COUNT 8
#define NX_MAX_FILE_SYSTEM_EPH_STRUCTS 4
#define NX_TX_MIN_CHECKPOINT_COUNT 4
#define NX_EPH_INFO_VERSION_1 1

#define MAX_CKSUM_SIZE 8

typedef uint64_t oid_t;
typedef uint64_t xid_t;
typedef unsigned char uuid_t[16];
typedef int64_t paddr_t;


typedef enum {
    NX_CNTR_OBJ_CKSUM_SET = 0,
    NX_CNTR_OBJ_CKSUM_FAIL = 1,
    NX_NUM_COUNTERS = 32
} nx_counter_id_t;


struct obj_phys {
    uint8_t o_cksum[MAX_CKSUM_SIZE];
    oid_t o_oid;
    xid_t o_xid;
    uint32_t o_type;
    uint32_t o_subtype;
};
typedef struct obj_phys obj_phys_t;


struct prange {
    paddr_t pr_start_paddr;
    uint64_t pr_block_count;
};
typedef struct prange prange_t;


struct nx_superblock {
    obj_phys_t nx_o;
    uint32_t nx_magic;
    uint32_t nx_block_size;
    uint64_t nx_block_count;
    uint64_t nx_features;
    uint64_t nx_readonly_compatible_features;
    uint64_t nx_incompatible_features;
    uuid_t nx_uuid;
    oid_t nx_next_oid;
    xid_t nx_next_xid;
    uint32_t nx_xp_desc_blocks;
    uint32_t nx_xp_data_blocks;
    paddr_t nx_xp_desc_base;
    paddr_t nx_xp_data_base;
    uint32_t nx_xp_desc_next;
    uint32_t nx_xp_data_next;
    uint32_t nx_xp_desc_index;
    uint32_t nx_xp_desc_len;
    uint32_t nx_xp_data_index;
    uint32_t nx_xp_data_len;
    oid_t nx_spaceman_oid;
    oid_t nx_omap_oid;
    oid_t nx_reaper_oid;
    uint32_t nx_test_type;
    uint32_t nx_max_file_systems;
    oid_t nx_fs_oid[NX_MAX_FILE_SYSTEMS];
    uint64_t nx_counters[NX_NUM_COUNTERS];
    prange_t nx_blocked_out_prange;
    oid_t nx_evict_mapping_tree_oid;
    uint64_t nx_flags;
    paddr_t nx_efi_jumpstart;
    uuid_t nx_fusion_uuid;
    prange_t nx_keylocker;
    uint64_t nx_ephemeral_info[NX_EPH_INFO_COUNT];
    oid_t nx_test_oid;
    oid_t nx_fusion_mt_oid;
    oid_t nx_fusion_wbc_oid;
    prange_t nx_fusion_wbc;
};


struct checkpoint_mapping {
    uint32_t cpm_type;
    uint32_t cpm_subtype;
    uint32_t cpm_size;
    uint32_t cpm_pad;
    oid_t cpm_fs_oid;
    oid_t cpm_oid;
    oid_t cpm_paddr;
};
typedef struct checkpoint_mapping checkpoint_mapping_t;


struct checkpoint_map_phys {
    obj_phys_t cpm_o;
    uint32_t cpm_flags;
    uint32_t cpm_count;
    checkpoint_mapping_t cpm_map[];
};
typedef struct checkpoint_map_phys checkpoint_map_phys_t;


struct nloc {
    uint16_t off;
    uint16_t len;
};
typedef struct nloc nloc_t;
#define BTOFF_INVALID 0xffff

#define BTNODE_FIXED_KV_SIZE 0x0004

struct btree_node_phys {
    obj_phys_t btn_o;
    uint16_t btn_flags;
    uint16_t btn_level;
    uint32_t btn_nkeys;
    nloc_t btn_table_space;
    nloc_t btn_free_space;
    nloc_t btn_key_free_list;
    nloc_t btn_val_free_list;
    uint64_t btn_data[];
};
typedef struct btree_node_phys btree_node_phys_t;


struct omap_key {
    oid_t ok_oid;
    xid_t ok_xid;
};
typedef struct omap_key omap_key_t;


struct omap_val {
    uint32_t ov_flags;
    uint32_t ov_size;
    paddr_t ov_paddr;
};
typedef struct omap_val omap_val_t;


struct j_key {
    uint64_t obj_id_and_type;
} __attribute__((packed));
typedef struct j_key j_key_t;
#define OBJ_ID_MASK 0x0fffffffffffffffULL
#define OBJ_TYPE_MASK 0xf000000000000000ULL
#define OBJ_TYPE_SHIFT 60


typedef enum {
    APFS_TYPE_ANY = 0,
    APFS_TYPE_SNAP_METADATA = 1,
    APFS_TYPE_EXTENT = 2,
    APFS_TYPE_INODE = 3,
    APFS_TYPE_XATTR = 4,
    APFS_TYPE_SIBLING_LINK = 5,
    APFS_TYPE_DSTREAM_ID = 6,
    APFS_TYPE_CRYPTO_STATE = 7,
    APFS_TYPE_FILE_EXTENT = 8,
    APFS_TYPE_DIR_REC = 9,
    APFS_TYPE_DIR_STATS = 10,
    APFS_TYPE_SNAP_NAME = 11,
    APFS_TYPE_SIBLING_MAP = 12,
    APFS_TYPE_MAX_VALID = 12,
    APFS_TYPE_MAX = 15,
    APFS_TYPE_INVALID = 15,
} j_obj_types;


struct j_drec_hashed_key {
    j_key_t hdr;
    uint32_t name_len_and_hash;
    uint8_t name[0];
} __attribute__((packed));
typedef struct j_drec_hashed_key j_drec_hashed_key_t;
#define J_DREC_LEN_MASK 0x000003ff
#define J_DREC_HASH_MASK 0xfffff400
#define J_DREC_HASH_SHIFT 10


struct j_drec_val {
    uint64_t file_id;
    uint64_t date_added;
    uint16_t flags;
    uint8_t xfields[];
} __attribute__((packed));
typedef struct j_drec_val j_drec_val_t;


typedef uint32_t cp_key_class_t;
typedef uint32_t cp_key_os_version_t;
typedef uint16_t cp_key_revision_t;
typedef uint32_t crypto_flags_t;


// typedef uint16_t mode_t;
#define S_IFMT 0170000
#define S_IFIFO 0010000
#define S_IFCHR 0020000
#define S_IFDIR 0040000
#define S_IFBLK 0060000
#define S_IFREG 0100000
#define S_IFLNK 0120000
#define S_IFSOCK 0140000
#define S_IFWHT 0160000


struct j_drec_key {
    j_key_t hdr;
    uint16_t name_len;
    uint8_t name[0];
} __attribute__((packed));
typedef struct j_drec_key j_drec_key_t;

typedef uint32_t uid_t;
typedef uint32_t gid_t;

struct j_inode_val {
    uint64_t parent_id;
    uint64_t private_id;
    uint64_t create_time;
    uint64_t mod_time;
    uint64_t change_time;
    uint64_t access_time;
    uint64_t internal_flags;
    union {
        int32_t nchildren;
        int32_t nlink;
    };
    cp_key_class_t default_protection_class;
    uint32_t write_generation_counter;
    uint32_t bsd_flags;
    uid_t owner;
    gid_t group;
    mode_t mode;
    uint16_t pad1;
    uint64_t pad2;
    uint8_t xfields[];
} __attribute__((packed));
typedef struct j_inode_val j_inode_val_t;


struct j_file_extent_key {
    j_key_t hdr;
    uint64_t logical_addr;
} __attribute__((packed));
typedef struct j_file_extent_key j_file_extent_key_t;


struct j_file_extent_val {
    uint64_t len_and_flags;
    uint64_t phys_block_num;
    uint64_t crypto_id;
} __attribute__((packed));
typedef struct j_file_extent_val j_file_extent_val_t;
#define J_FILE_EXTENT_LEN_MASK 0x00ffffffffffffffULL
#define J_FILE_EXTENT_FLAG_MASK 0xff00000000000000ULL
#define J_FILE_EXTENT_FLAG_SHIFT 56



void get_descriptors(char const *path, nx_superblock_t **descriptors);
void get_backup(char const *path, nx_superblock_t *backup);


#endif
