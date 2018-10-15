#include <assert.h>

#include "secure-module.h"

#include "./external/trezor/bip39.h"
#include "./external/trezor/memzero.h"

#include <ecc_key.h>
#include <bip32.h>
#include <ecc.h>

int sign(const uint8_t key[PRIVATE_KEY_SIZE + ENCRYPTION_OVERLOAD], const uint8_t msg[SHA256_SIZE], uint8_t* out)
{
  char *sig[65] = { 0 };


  return 0;
}


int exportPhrase(const uint8_t entropy[ENTROPY_SIZE + ENCRYPTION_OVERLOAD], str_t* out)
{

  return 0;
}


full_key_t * createKey()
{
  full_key_t* newKey = calloc(1, sizeof(*newKey));
  if(newKey == NULL) {
    return NULL;
  }
  
  // char *mnemonic = mnemonic_generate(MIN_ENTROPY);
  char *mnemonic = "radio burst level stove exclude violin chief destroy relax depend basket shed";
  uint8_t* tmp = calloc(32, sizeof(uint8_t));

  int status = 0;
  status = mnemonic_to_entropy(mnemonic, tmp);
  if(!status) {
    free(newKey);
    return NULL;
  }

	memcpy(newKey->entropy, tmp, 16);
  // assert(newKey->entropy[16] == 0);
  memset(tmp, 0, 32);

  // sanity check: string should (still) be null terminated
  assert(newKey->entropy[17] == 0);

  uint8_t seed[64];
  mnemonic_to_seed(mnemonic, "", seed, NULL);

  // DEV TEST
  char* m = mnemonic_from_data(newKey->entropy, 16);

  btc_hdnode hdnode;
  status = btc_hdnode_from_seed(seed, 64, &hdnode);
  if(!status) {
    free(newKey);
    return NULL;
  }

  return 0;
}
