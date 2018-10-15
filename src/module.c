#include "secure-module-js.h"

#define DECLARE_NAPI_METHOD(name, func)     \
  {                                         \
    name, 0, func, 0, 0, 0, napi_default, 0 \
  }

napi_ref constructorRef;

napi_value InstanciateSecureModule(napi_env env, napi_callback_info info)
{
  DEBUG("SecureModule::Instanciate intantiation...");

  napi_status status;

  // Check if called with "new" keyword
  napi_value target = NULL;
  status = napi_get_new_target(env, info, &target);
  ASSERT(env, status == napi_ok, "Failed to get \"new\" target");
  ASSERT(env, target != NULL, "Must be called with new");

  // Check if called with argument (it should not be)
  size_t argc = 0;
  status = napi_get_cb_info(env, info, &argc, NULL, nullptr, nullptr);
  ASSERT(env, status == napi_ok, "Failed to get arguments");
  DEBUG("SecureModule::Instanciate argc=%ld", argc);
  ASSERT(env, argc == 0, "Expecting no argument");

  // Get JS constructor
  napi_value cons = NULL;
  status = napi_get_reference_value(env, constructorRef, &cons);
  ASSERT(env, status == napi_ok, "Failed to get contructor");

  // Create JS instance
  napi_value instance = NULL;
  status = napi_new_instance(env, cons, argc, NULL, &instance);
  ASSERT(env, status == napi_ok, "Failed to create new instance");

  DEBUG("SecureModule::Instanciate instance=%p", instance);

  return instance;
}

/**
 * Used to declare JS "class" SecureModule
 */
napi_value ExportModule(napi_env env, napi_value exports)
{
  // Define module interface
  DEBUG("SecureModule declaration...");

  napi_status status;
  napi_property_descriptor properties[] = {
      DECLARE_NAPI_METHOD("plusOne", PlusOne),
      DECLARE_NAPI_METHOD("init", Init)
  };

  // Define JS class
  napi_value cons;
  status = napi_define_class(env, "SecureModule", NAPI_AUTO_LENGTH, New, nullptr, 2, properties, &cons);
  ASSERT(env, status == napi_ok, "Failed to define class");

  // Create reference to JS contructor
  status = napi_create_reference(env, cons, 1, &constructorRef);
  ASSERT(env, status == napi_ok, "Failed to reference contructor");

  // Export module
  status = napi_create_function(env, "SecureModule", NAPI_AUTO_LENGTH, InstanciateSecureModule, nullptr, &exports);
  ASSERT(env, status == napi_ok, "Failed to bind class to native module");
  return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, ExportModule);
