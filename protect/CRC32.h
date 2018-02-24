#pragma once



void init_crc_table(void);
unsigned int crc32(unsigned int crc, unsigned char * buffer, unsigned int size);
//static int calc_img_crc(const char * in_file, unsigned int * img_crc);