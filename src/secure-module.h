#ifndef WRAP_SECURE_MODULE_H_
#define WRAP_SECURE_MODULE_H_

#include <stdint.h>
#include <stddef.h>

#define MIN_ENTROPY 128

#define ENCRYPTION_OVERLOAD       0 // 16
#define PRIVATE_KEY_SIZE          32 + 1 // initial length + NULL terminated character
#define ENTROPY_SIZE              16 + 1 // initial length + NULL terminated character
#define PUBLIC_KEY_SIZE           25 + 1 // initial length + NULL terminated character
#define SHA256_SIZE               32 + 1 // initial length + NULL terminated character

/**
 * Buffer type
 * Return type of sign
 */
typedef struct {
  size_t len;
  uint8_t *data;
} buf_t;

/**
 * String type
 * Return type of sign
 */
typedef buf_t str_t;

/**
 * Return type of createKey
 */
typedef struct {
  uint8_t privateKey[PRIVATE_KEY_SIZE + ENCRYPTION_OVERLOAD];
  uint8_t entropy[ENTROPY_SIZE + ENCRYPTION_OVERLOAD];
  uint8_t publicKey[PUBLIC_KEY_SIZE];
} full_key_t;

#endif // WRAP_SECURE_MODULE_H_
