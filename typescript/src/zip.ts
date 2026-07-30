/**
 * Чтение и запись zip без сжатия и без зависимостей.
 *
 * Пакет .seal собирается хранением, а не сжатием, намеренно: тогда
 * верификатору не нужен распаковщик, и разбор сводится к каталогу и нарезке
 * байтов. Читатель принимает и сжатые записи, если их создал кто-то другой, —
 * через встроенный zlib.
 */

import { inflateRawSync } from "node:zlib";

import { FormatError } from "./core.js";

const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();

export function crc32(buf: Buffer): number {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) {
    c = CRC_TABLE[(c ^ buf[i]!) & 0xff]! ^ (c >>> 8);
  }
  return (c ^ 0xffffffff) >>> 0;
}

/**
 * Верификатор по определению обрабатывает файл, полученный от противоположной
 * стороны. Без пределов присланный архив в мегабайт кладёт машину
 * проверяющего. Законный пакет на порядки меньше.
 */
export const MAX_ENTRIES = 512;
export const MAX_ENTRY_BYTES = 64 * 1024 * 1024;
export const MAX_TOTAL_BYTES = 128 * 1024 * 1024;

function safeName(name: string): string {
  const n = name.replace(/\\/g, "/");
  if (n.startsWith("/")) throw new FormatError(`недопустимое имя в архиве: ${name}`);
  for (const part of n.split("/")) {
    if (part === ".." || part === ".") {
      throw new FormatError(`имя в архиве выходит за его пределы: ${name}`);
    }
  }
  return name;
}

export interface ZipEntry {
  name: string;
  data: Buffer;
}

export function writeZip(entries: ZipEntry[]): Buffer {
  const locals: Buffer[] = [];
  const centrals: Buffer[] = [];
  let offset = 0;

  for (const e of entries) {
    const name = Buffer.from(e.name, "utf8");
    const crc = crc32(e.data);

    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0);
    lh.writeUInt16LE(20, 4);       // версия
    lh.writeUInt16LE(0x0800, 6);   // имена в UTF-8
    lh.writeUInt16LE(0, 8);        // без сжатия
    lh.writeUInt16LE(0, 10);       // время
    lh.writeUInt16LE(0x21, 12);    // дата: 1980-01-01, чтобы сборка была воспроизводимой
    lh.writeUInt32LE(crc, 14);
    lh.writeUInt32LE(e.data.length, 18);
    lh.writeUInt32LE(e.data.length, 22);
    lh.writeUInt16LE(name.length, 26);
    lh.writeUInt16LE(0, 28);
    locals.push(lh, name, e.data);

    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(0x02014b50, 0);
    ch.writeUInt16LE(20, 4);
    ch.writeUInt16LE(20, 6);
    ch.writeUInt16LE(0x0800, 8);
    ch.writeUInt16LE(0, 10);
    ch.writeUInt16LE(0, 12);
    ch.writeUInt16LE(0x21, 14);
    ch.writeUInt32LE(crc, 16);
    ch.writeUInt32LE(e.data.length, 20);
    ch.writeUInt32LE(e.data.length, 24);
    ch.writeUInt16LE(name.length, 28);
    ch.writeUInt32LE(offset, 42);
    centrals.push(ch, name);

    offset += lh.length + name.length + e.data.length;
  }

  const central = Buffer.concat(centrals);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(central.length, 12);
  eocd.writeUInt32LE(offset, 16);

  return Buffer.concat([...locals, central, eocd]);
}

export function readZip(buf: Buffer): Map<string, Buffer> {
  let eocd = -1;
  for (let i = buf.length - 22; i >= 0 && i > buf.length - 65558; i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) throw new FormatError("это не zip-архив");

  const count = buf.readUInt16LE(eocd + 10);
  let off = buf.readUInt32LE(eocd + 16);
  const out = new Map<string, Buffer>();
  if (count > MAX_ENTRIES) {
    throw new FormatError(`в архиве ${count} записей, предел ${MAX_ENTRIES}`);
  }
  let total = 0;

  for (let i = 0; i < count; i++) {
    if (off + 46 > buf.length) throw new FormatError("каталог архива обрывается");
    if (buf.readUInt32LE(off) !== 0x02014b50) {
      throw new FormatError("повреждён каталог архива");
    }
    const method = buf.readUInt16LE(off + 10);
    const csize = buf.readUInt32LE(off + 20);
    const size = buf.readUInt32LE(off + 24);
    const nlen = buf.readUInt16LE(off + 28);
    const elen = buf.readUInt16LE(off + 30);
    const clen = buf.readUInt16LE(off + 32);
    const lho = buf.readUInt32LE(off + 42);
    const name = safeName(buf.subarray(off + 46, off + 46 + nlen).toString("utf8"));
    if (size > MAX_ENTRY_BYTES) {
      throw new FormatError(
        `${name}: заявлено ${size} байт, предел ${MAX_ENTRY_BYTES} — архивная бомба`);
    }
    total += size;
    if (total > MAX_TOTAL_BYTES) {
      throw new FormatError(`суммарный размер архива превышает ${MAX_TOTAL_BYTES}`);
    }

    if (lho + 30 > buf.length || buf.readUInt32LE(lho) !== 0x04034b50) {
      throw new FormatError("повреждён заголовок файла");
    }
    const dataOff = lho + 30 + buf.readUInt16LE(lho + 26) + buf.readUInt16LE(lho + 28);
    if (dataOff + csize > buf.length) {
      throw new FormatError(`запись ${name} обрывается`);
    }
    const raw = buf.subarray(dataOff, dataOff + csize);
    // Заголовок может лгать о размере, поэтому распаковка ограничена явно.
    const data = method === 0
      ? raw
      : inflateRawSync(raw, { maxOutputLength: MAX_ENTRY_BYTES });
    out.set(name, data);

    off += 46 + nlen + elen + clen;
  }
  return out;
}
