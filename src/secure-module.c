#include <assert.h>
#include <stdbool.h>

#include "secure-module.h"

#include "./external/trezor/bip39.h"
#include "./external/trezor/memzero.h"

#include <ecc_key.h>
#include <bip32.h>
#include <ecc.h>

#define MIN_ENTROPY 128

#define debug 0

#define DEBUG(str, ...) \
  fprintf(stdout,"%s(%u): " str "\n", __FILE__, __LINE__, ##__VA_ARGS__)

#define MEMCLEAR(s) memset(&s, 0, sizeof(s))

void hexdump(const void* data, size_t size) {
	char ascii[17];
	size_t i, j;
	ascii[16] = '\0';
	for (i = 0; i < size; ++i) {
		printf("%02X ", ((unsigned char*)data)[i]);
		if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
			ascii[i % 16] = ((unsigned char*)data)[i];
		} else {
			ascii[i % 16] = '.';
		}
		if ((i+1) % 8 == 0 || i+1 == size) {
			printf(" ");
			if ((i+1) % 16 == 0) {
				printf("|  %s \n", ascii);
			} else if (i+1 == size) {
				ascii[(i+1) % 16] = '\0';
				if ((i+1) % 16 <= 8) {
					printf(" ");
				}
				for (j = (i+1) % 16; j < 16; ++j) {
					printf("   ");
				}
				printf("|  %s \n", ascii);
			}
		}
	}
}

int sign(const uint8_t key[PRIVATE_KEY_SIZE + ENCRYPTION_OVERLOAD], const uint8_t msg[SHA256_SIZE], uint8_t* out)
{
  char *sig[65] = { 0 };


  return 0;
}


int exportPhrase(const uint8_t entropy[ENTROPY_SIZE + ENCRYPTION_OVERLOAD], str_t* out)
{

  return 0;
}

void initModule() {
  btc_ecc_start();
}

full_key_t* createKey()
{
  full_key_t* newKey = calloc(1, sizeof(*newKey));
  if(newKey == NULL) {
    return NULL;
  }

  char *mnemonic = mnemonic_generate(MIN_ENTROPY);
  // char *mnemonic = "radio burst level stove exclude violin chief destroy relax depend basket shed";
  uint8_t tmp[32] = { 0 };

  bool status = false;
  status = mnemonic_to_entropy(mnemonic, tmp);
  if(!status) {
    free(newKey);
    return NULL;
  }

	memcpy(newKey->entropy, tmp, 16);
  MEMCLEAR(tmp);

  uint8_t seed[64];
  mnemonic_to_seed(mnemonic, "", seed, NULL);
  MEMCLEAR(mnemonic);

  char* m = mnemonic_from_data(newKey->entropy, 16);

  btc_hdnode hdnode;
  status = btc_hdnode_from_seed(seed, 64, &hdnode);
  MEMCLEAR(seed);
  if(!status) {
    free(newKey);
    return NULL;
  }

  // In place derivation
  status = btc_hd_generate_key(&hdnode, "m/44'/0'/0'", hdnode.private_key, hdnode.chain_code, false);
  if(!status) {
    free(newKey);
    return NULL;
  }

  memcpy(newKey->privateKey, hdnode.private_key, PRIVATE_KEY_SIZE - 1);
  btc_hdnode_get_p2pkh_address(&hdnode, &btc_chainparams_main, newKey->publicKey, sizeof(newKey->publicKey));
  MEMCLEAR(hdnode);

  return newKey;
}
