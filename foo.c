#include "crypto.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "ore_blk.h"

void test(const char key[16]) {
  printf("key = '%s'\n", key);
}

int main(int argc, char **args) {
  char key[] = "abcdefghij";
  test(key);

  return 0;
}
