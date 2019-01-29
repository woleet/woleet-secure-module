# Woleet secure moodule
## Prerequisite

node 10, npm, compiler C/C++, debhelper

## Development mode:
#### Install the node packages:
    $ npm install

#### Install libbtc (limited to minimal tools) in /usr/local/lib/ & /usr/local/include:
    $ git clone git@github.com:libbtc/libbtc.git
    $ cd libbtc
    $ ./autogen.sh
    $ ./configure --disable-wallet --disable-tools --disable-net CC=/usr/bin/clang CXX=/usr/bin/clang++
    $ make check
    $ make install

#### Build 
    npx node-gyp configure build

#### Run development draft: 
    ENCRYPTION_SECRET='secret' node --expose-gc draft.js

#### Setup development environment (vscode + nvm)

In the `".vscode/c_cpp_properties.json"` file add `"/path/to/.nvm/versions/node/v10.9.0/include/node"`
