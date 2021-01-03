#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

// Enable both ECB and CBC mode. Note this can be done before including aes.h or at compile-time.
// E.g. with GCC by using the -D flag: gcc -c aes.c -DCBC=0 -DECB=1
#define CBC 1
#define ECB 1

#include "aes.h"

uint8_t len = 0;

static void phex(uint8_t *str);
static void test_ecb_verbose(uint8_t *plaintext, uint8_t *key);

int main(void)
{

#ifdef AES128
  len = 16;
  printf("\nTesting AES128\n\n");
#elif defined(AES192)
  len = 24;
  printf("\nTesting AES192\n\n");
#elif defined(AES256)
  len = 32;
  printf("\nTesting AES256\n\n");
#else
  printf("You need to specify a symbol between AES128, AES192 or AES256. Exiting");
  return 0;
#endif
  char *s;

  printf("Input Text: ");
  s = malloc(len * sizeof(char));
  scanf("%[^\n]", s);
  s = realloc(s, strlen(s) + 1);

  getchar();

  char *k;
  printf("Key: ");
  k = malloc(len * sizeof(char));
  scanf("%[^\n]", k);
  k = realloc(k, strlen(k) + 1);
  printf("\n\n********************************************\n");

  uint8_t *plaintext = (uint8_t *)malloc(len * sizeof(uint8_t));
  uint8_t *key = (uint8_t *)malloc(len * sizeof(uint8_t));

  for (int i = 0; i < len; i++)
  {
    plaintext[i] = (uint8_t)s[i];
    key[i] = (uint8_t)k[i];
  }

  test_ecb_verbose(plaintext, key);

  return 0;
}

// prints string as hex
static void phex(uint8_t *str)
{
  unsigned char i;
  for (i = 0; i < len; ++i)
    printf("%c", str[i]);
  printf("\n");
}

static void test_ecb_verbose(uint8_t *plaintext, uint8_t *key)
{
  clock_t start, end;
  uint8_t buf[len], buf2[len];

  memset(buf, 0, len);
  memset(buf2, 0, len);

  printf("ECB encrypt verbose:\n\n");
  start = clock();
  printf("plain text:\n");
  phex(plaintext);
  printf("\n");

  printf("key:\n");
  phex(key);
  printf("\n");

  printf("ciphertext:\n");
  AES_ECB_encrypt(plaintext, key, buf, len);
  end = clock();
  phex(buf);
  printf("\nEncryption executing duration: %f\n", ((double)(end - start)) / CLOCKS_PER_SEC);

  printf("\n*******************************************\n");

  printf("ECB decrypt verbose:\n\n");
  start = clock();
  printf("ciphertext:\n");
  phex(buf);
  printf("\n");

  printf("key:\n");
  phex(key);
  printf("\n");

  printf("plain text:\n");
  AES_ECB_decrypt(buf, key, buf2, len);
  phex(buf2);
  end = clock();
  printf("\nDecryption executing duration: %f", ((double)(end - start)) / CLOCKS_PER_SEC);
  printf("\n");
}