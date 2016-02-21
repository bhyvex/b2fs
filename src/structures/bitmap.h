#ifndef B2FS_BITMAP_H
#define B2FS_BITMAP_H

/*----- Numerical Constants -----*/

#define BITMAP_SUCCESS 0x00
#define BITMAP_FULL_ERROR -0x01
#define BITMAP_OCCUPIED_ERROR -0x02
#define BITMAP_VACANT_ERROR -0x04
#define BITMAP_RANGE_ERROR -0x08

/*----- Type Declarations -----*/

typedef struct bitmap bitmap_t;

/*----- Function Declaractions -----*/

bitmap_t *create_bitmap(int size);
void destroy_bitmap(bitmap_t *bits);

int set_bit(bitmap_t *bits, int bit);
int clear_bit(bitmap_t *bits, int bit);
int check_bit(bitmap_t *bits, int bit);
int reserve(bitmap_t *bits);

#endif
