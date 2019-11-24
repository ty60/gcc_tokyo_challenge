#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_BUF 190
typedef struct{
    unsigned char raw[MAX_BUF];
    unsigned int checksum;
    unsigned int checksum2;
}simple_format;

void crash(int id) {
    printf("Congratulation!\nYou got a crash (id: %d)\n", id);  
    *((unsigned int *)1) = 1;
}


long read_file(char *path, unsigned char **newbuf) {
    FILE *fp;
    if ((fp = fopen(path, "r")) == NULL) {
        fprintf(stderr, "Failed to open %s\n", path);
        exit(EXIT_FAILURE);
    }
    fseek(fp, 0L, SEEK_END);
    long sz = ftell(fp);
    *newbuf = (unsigned char *) malloc(sz + 1);
    fseek(fp, 0L, SEEK_SET);
    fread(*newbuf, sizeof(unsigned char), sz, fp);
    (*newbuf)[sz] = 0; // NULL terminate
    fclose(fp);
    return sz;
}

int main(int argc, char *argv[]){
    if (argc < 2) {
        fprintf(stderr, "usage ./simple_linter <input-file>\n");
        exit(EXIT_FAILURE);
    }
    unsigned char *buf = NULL;
    long size = read_file(argv[1], &buf);
    /* Check magic number (short) */
    if (size > 1 && buf[0] == 0xde && buf[1] == 0xad) {
        crash(0);
    }
  
    /* Check magic number (long) */
    if (strcmp(buf, "MAGICHDR") == 0) {
        crash(1);
    }
  
    if (size >= sizeof(simple_format)) {
        simple_format sf;
        memcpy(&sf, buf, sizeof(simple_format));
        int i;
        unsigned int sum = 0, sum2 = 0;
        for (i = 0; i < MAX_BUF - 1; i+=2) sum += (sf.raw[i] | sf.raw[i + 1] << 8);
        for (i = 0; i < MAX_BUF - 1; i+=2) sum2 += (sf.raw[i + 1] | sf.raw[i] << 8);
        if (sum == sf.checksum && sum2 == sf.checksum2) {
            printf("Wow you passed the checksum validation!\n");
            crash(2);
        }
    }

    if (buf)
        free(buf);
}
