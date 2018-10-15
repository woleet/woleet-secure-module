const SecureModule = require('./build/Release/module');

console.log({SecureModule});

function gc() {
  if (global.gc) {
    global.gc();
  } else {
    console.log('Garbage collection unavailable.  Pass --expose-gc when launching node to enable forced garbage collection.');
  }
}

let sm1 = new SecureModule();
let sm2 = new SecureModule();

console.log({sm1});

console.log(sm1.init());
console.log(sm1.plusOne());
// console.log(sm1.plusOne());

sm1 = null;

gc();

sm2 = null;

setTimeout(gc, 1000);

setTimeout(() => console.log('done.'), 3000);
