#ifndef WRAP_SECURE_MODULE_JS_H_
#define WRAP_SECURE_MODULE_JS_H_

#include <node_api.h>
#include <stdio.h>

#define ASSERT(env, test, msg)        \
  if (!(test)) {                      \
    napi_throw_error(env, NULL, msg); \
    return NULL;                      \
  }

#define DBG true

#if DBG
#define DEBUG(str, ...) \
  fprintf(stdout,"%s(%u): " str "\n", __FILE__, __LINE__, ##__VA_ARGS__)
static int globalCounter = 0;
#else
  #define DEBUG( ... )
#endif

#define nullptr NULL

void Destructor(napi_env env, void* nativeObject, void* finalize_hint);

napi_value New(napi_env env, napi_callback_info info);
napi_value PlusOne(napi_env env, napi_callback_info info);
napi_value Init(napi_env env, napi_callback_info info);

/*
  counter_;
  char *secret;
  napi_env env_;
*/

typedef struct {
  #if DBG
    int id;
  #endif
  unsigned char initialized;
  unsigned char counter;
  char *secret;
  napi_env env_;
  napi_ref wrapper_;
} secure_module_instance_t;

#endif // WRAP_SECURE_MODULE_JS_H_
