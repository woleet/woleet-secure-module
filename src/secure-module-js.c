#include "secure-module-js.h"
#include "secure-module.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

// SecureModule::SecureModule() : env_(nullptr), wrapper_(nullptr) {}

// SecureModule::~SecureModule() { napi_delete_reference(env_, wrapper_); }

#define DECLARE_NAPI_METHOD(name, func)     \
  {                                         \
    name, 0, func, 0, 0, 0, napi_default, 0 \
  }

void Destructor(napi_env env, void *nativeObject, void * finalize_hint)
{
  secure_module_instance_t *obj = nativeObject;
  DEBUG("Instance %d beeing garbage collected", obj->id);
}

napi_value New(napi_env env, napi_callback_info info)
{
  napi_status status;
  DEBUG("SecureModule::New -> Instanciating new SecureModule...");

  size_t argc = 0;
  napi_value jsthis = NULL;
  status = napi_get_cb_info(env, info, &argc, NULL, &jsthis, nullptr);
  ASSERT(env, status == napi_ok, "Failed to get arguments");

  DEBUG("SecureModule::New argc=%ld this=%p", argc, jsthis);

  secure_module_instance_t *obj = calloc(1, sizeof(secure_module_instance_t));

  #if DBG
    obj->id = ++globalCounter;
  #endif

  obj->initialized = false;

  obj->env_ = env;
  status = napi_wrap(env, jsthis, obj, Destructor, nullptr, &obj->wrapper_);
  ASSERT(env, status == napi_ok, "Failed to retreive native structure");
  DEBUG("SecureModule::New id=%d   this=%p", obj->id, jsthis);
  return jsthis;
}

napi_value Init(napi_env env, napi_callback_info info)
{
  napi_status status;

  napi_value jsthis;
  status = napi_get_cb_info(env, info, nullptr, nullptr, &jsthis, nullptr);
  ASSERT(env, status == napi_ok, "Invalid type");

  secure_module_instance_t *obj;
  status = napi_unwrap(env, jsthis, (void**) &obj);
  ASSERT(env, status == napi_ok, "Failed to get this");

  // Get password from environment
  const char* secret = getenv("ENCRYPTION_SECRET");
  DEBUG("SecureModule::Init secret=\"%s\"", secret);
  ASSERT(env, secret != NULL, "Missing environment variable \"ENCRYPTION_SECRET\"");

  napi_value num;
  status = napi_create_double(env, obj->counter, &num);
  assert(status == napi_ok);

  return NULL;
}

napi_value PlusOne(napi_env env, napi_callback_info info)
{
  napi_status status;

  napi_value jsthis;
  status = napi_get_cb_info(env, info, nullptr, nullptr, &jsthis, nullptr);
  ASSERT(env, status == napi_ok, "Invalid type");

  secure_module_instance_t *obj;
  status = napi_unwrap(env, jsthis, (void**) &obj);
  ASSERT(env, status == napi_ok, "Failed to get this");

  obj->counter++;

  DEBUG("SecureModule::CREATE KEY");
  full_key_t* key = createKey();

  DEBUG("SecureModule::CREATED KEY %d", sizeof(key->entropy));

  napi_value num;
  status = napi_create_double(env, obj->counter, &num);
  ASSERT(env, status == napi_ok, "Failed to create number");

  return num;
}
