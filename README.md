# Woleet Secure Module

This module is used by Woleet.ID Server to manage:
- encryption/decryption functions
- key generation and import/export functions.

The idea is to keep all sensitive data isolated in this moduleto improve security and to allow different implementations.

## Prerequisite

node >=10, npm

## Development mode:

### Install Node packages

    $ npm install

### Test secure module

- Set the environement variable ENCRYPTION_SECRET to any value
- Start the tests:

    $ npm test

### Build secure module

    $ npm run build
