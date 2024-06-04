#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <assert.h>
#include <time.h>

#include "../ncsnet/msm.h"
#include "../ncsnet/utils.h"

int main(void)
{
  for (int i = 0; i < 10; i++) {
    u32 seed = random_seed_u32();
    msm_seed(seed);
    printf("%u\n", msm());
  }
  return 0;
}
