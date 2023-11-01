var buff = Buffer.alloc(5);
console.log(Buffer.byteLength(buff));
buff.write("hew adasdasda");
console.log(buff.toString('utf-8'));

import { randomBytes } from 'node:crypto';
  var rando = await randomBytes(16);
  console.log(rando.toString('ascii'));

  import fs from 'fs';
  var data2 = fs.readFileSync('file2.txt');
  var data1 = fs.readFileSync('file1.txt');
  
  var conc = Buffer.concat([data1,data2])

  const uint8 = new Uint8Array(2);
  uint8[0] = 42;
  console.log(uint8[1]); // 42
console.log(uint8.length); // 2
console.log(uint8.BYTES_PER_ELEMENT); // 1


// Creates an ArrayBuffer with a size of 10 bytes
const abuf = new ArrayBuffer(16);
 
console.log(abuf.byteLength);
// Output: 10


const buf = Buffer.from("😀", "utf-8");
const arr8 = new Uint8Array(
  buf.buffer,
  buf.byteOffset,
  buf.length / Uint8Array.BYTES_PER_ELEMENT
  );
console.log(Buffer.from(arr8).toString('utf-8'));


const str = "😇🙂😙😚😗";



function ab2str(buf) {
    return String.fromCharCode.apply(null, new Uint16Array(buf));
}
function str2ab(str) {
    var buf = new ArrayBuffer(str.length*2); // 2 bytes for each char
    var bufView = new Uint16Array(buf);
    for (var i=0, strLen=str.length; i < strLen; i++) {
    bufView[i] = str.charCodeAt(i);
    }
    return buf;
}
const ab = str2ab(str);
console.log(ab2str(ab));


console.log(Buffer.from(str).toString('hex'));

console.log(Buffer.from("f09f9887f09f9982f09f9899f09f989af09f9897", 'hex').toString('utf-8'))


console.log(Buffer.from("鿰螘鿰芙鿰馘鿰骘鿰鞘", 'utf16le').toString('utf16le'))