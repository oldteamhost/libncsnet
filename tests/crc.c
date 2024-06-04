#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <assert.h>

#include "../ncsnet/crc.h"
#include "../ncsnet/sctp.h"
#include "../ncsnet/ip.h" 

u32 crc32(const u8 *buf, size_t len, const u32 *customtab);
u32 crc32updt(u32 crc, u8 val);

void test_crc32(void)
{
  const u8 data1[] = "123456789";
  u32 result1 = crc32(data1, 9, NULL);
  assert(result1 == 0xCBF43926);
  
  const u8 data2[] = "Hello, World!";
  u32 result2 = crc32(data2, 13, NULL);
  assert(result2 == 0xEC4AC3D0); 
  
  const u8 data3[] = "";
  u32 result3 = crc32(data3, 0, NULL);
  assert(result3 == 0);
}


void test_crc32updt(void)
{
  const u8 data[] = "123456789";
  u32 crc = 0xFFFFFFFF;
  
  for (size_t i = 0; i < 9; i++)
    crc = crc32updt(crc, data[i]);
  
  crc ^= 0xFFFFFFFF;
  assert(crc == 0xCBF43926);
}

int main(void)
{
  test_crc32();
  test_crc32updt();
  printf("aeee\n");

  int fd;
  char *chunk = NULL;
  int chunklen = 0;
  
  fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  
  chunklen = sizeof(struct sctp_chunk_hdr_init);
  chunk = (char*)malloc(chunklen);
  sctp_pack_chunkhdr_init(chunk, SCTP_INIT, 0, chunklen,
			  random_u32(), 32768, 10, 2048, random_u32());
  
  sctp4_send_pkt(NULL, fd, inet_addr("192.168.1.38"),
		 inet_addr("45.33.32.156"), 121, false, NULL, 0,
		 random_srcport(), 80, chunk, chunklen, 0, NULL, 0,
		 0, false, false);

  free(chunk);
  close(fd);
  return 0;
}
