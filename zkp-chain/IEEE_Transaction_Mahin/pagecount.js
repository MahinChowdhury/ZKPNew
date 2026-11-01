// pagecount.js — print the page count of a PDF (no external deps).
// Usage: node pagecount.js ieee-paper.pdf [maxPages]
// Exits 1 if the count exceeds maxPages (default 13, the IEEE TIFS limit).
const fs = require("fs");
const zlib = require("zlib");

const file = process.argv[2] || "ieee-paper.pdf";
const max = parseInt(process.argv[3] || "13", 10);
const buf = fs.readFileSync(file);
const raw = buf.toString("latin1");

// Collect plain text plus every inflatable stream (object streams hide /Type /Page)
const chunks = [raw];
const re = /stream\r?\n/g;
let m;
while ((m = re.exec(raw))) {
  const start = m.index + m[0].length;
  const end = raw.indexOf("endstream", start);
  if (end < 0) break;
  try { chunks.push(zlib.inflateSync(buf.subarray(start, end)).toString("latin1")); } catch { /* not flate */ }
}
const text = chunks.join("\n");
const pages = (text.match(/\/Type\s*\/Page(?![a-zA-Z])/g) || []).length;
console.log(`${file}: ${pages} pages (limit ${max})`);
process.exit(pages > max ? 1 : 0);
