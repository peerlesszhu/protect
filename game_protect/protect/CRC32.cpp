#include "stdafx.h"
#include "CRC32.h"
#include <stdio.h>  
#include <stdlib.h> 
#include <string.h>  


#define BUFSIZE     1024*4  

unsigned int crc_table[256];

void init_crc_table(void)
{
	unsigned int c;
	unsigned int i, j;

	for (i = 0; i < 256; i++) {
		c = (unsigned int)i;
		for (j = 0; j < 8; j++) {
			if (c & 1)
				c = 0xedb88320L ^ (c >> 1);
			else
				c = c >> 1;
		}
		crc_table[i] = c;
	}
}

/*第一次传入的值需要固定,如果发送端使用该值计算crc校验码,
**那么接收端也同样需要使用该值进行计算*/
//unsigned int crc = 0xffffffff;
unsigned int crc32(unsigned int crc, unsigned char *buffer, unsigned int size)
{
	unsigned int i;
	for (i = 0; i < size; i++) {
		crc = crc_table[(crc ^ buffer[i]) & 0xff] ^ (crc >> 8);
	}
	return crc;
}


//int calc_img_crc(const char *in_file, unsigned int *img_crc)
//{
//	int fd;
//	int nread;
//	int ret;
//	unsigned char buf[BUFSIZE];
//	/*第一次传入的值需要固定,如果发送端使用该值计算crc校验码,
//	**那么接收端也同样需要使用该值进行计算*/
//	unsigned int crc = 0xffffffff;
//
//	fd = open(in_file, O_RDONLY);
//	if (fd < 0) {
//		printf("%d:open %s.\n", __LINE__, strerror(errno));
//		return -1;
//	}
//
//	while ((nread = read(fd, buf, BUFSIZE)) > 0) {
//		crc = crc32(crc, buf, nread);
//	}
//	*img_crc = crc;
//
//	close(fd);
//
//	if (nread < 0) {
//		printf("%d:read %s.\n", __LINE__, strerror(errno));
//		return -1;
//	}
//
//	return 0;
//}