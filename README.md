# Woleet Secure Module

This NodeJS module is used by Woleet.ID Server to manage:
- key generation functions
- key import/export functions
- signature functions (path derivation is supported)
- encryption/decryption functions

Woleet.ID Server sensitive data are isolated in this module to improve security and ease new implementations.

## Prerequisite

node >=10, npm

## Development mode:

### Install Node packages

    $ npm install

### Test secure module

- Set the environment variable ENCRYPTION_SECRET to any value
- Start the tests:

    $ npm test

### Build secure module

    $ npm run build
