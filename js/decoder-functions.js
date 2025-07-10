function decodeText() {
  const input = document.getElementById("decode-input").value;
  const format = document.getElementById("decode-format").value;
  const resultContainer = document.getElementById("decode-result");

  if (!input.trim()) {
    resultContainer.innerHTML =
      '<div class="error">Please enter text to decode</div>';
    return;
  }

  showLoading("decode-result"); // Assumed function to show loading indicator

  setTimeout(() => {
    try {
      let result = "";

      switch (format) {
        case "auto":
          result = autoDetectAndDecode(input);
          break;
        case "base64":
          result = atob(input);
          break;
        case "base32":
          result = base32Decode(input);
          break;
        case "base16":
        case "hex":
          result = hexToString(input);
          break;
        case "binary":
          result = binaryToString(input);
          break;
        case "octal":
          result = octalToString(input);
          break;
        case "url":
          result = decodeURIComponent(input);
          break;
        case "html":
          result = htmlDecode(input);
          break;
        case "xml":
          result = xmlDecode(input);
          break;
        case "rot13":
          result = rot13(input);
          break;
        case "rot47":
          result = rot47(input);
          break;
        case "caesar":
          const shift =
            parseInt(document.getElementById("shift-value").value) || 3;
          result = caesarCipher(input, -shift);
          break;
        case "atbash":
          result = atbashCipher(input);
          break;
        case "morse":
          result = morseDecode(input);
          break;
        case "bacon":
          result = baconDecode(input);
          break;
        case "reverse":
          result = input.split("").reverse().join("");
          break;
        case "ascii":
          result = asciiToString(input);
          break;
        case "phonetic":
          result = phoneticDecode(input);
          break;
        case "base85":
          result = base85Decode(input);
          break;
        case "base58":
          result = base58Decode(input);
          break;
        case "base36":
          result = base36Decode(input);
          break;
        case "uuencode":
          result = uuDecode(input);
          break;
        case "xxencode":
          result = xxDecode(input);
          break;
        case "yencode":
          result = yDecode(input);
          break;
        case "quoted-printable":
          result = quotedPrintableDecode(input);
          break;
        case "punycode":
          result = punycodeDecode(input);
          break;
        case "rot5":
          result = rot5(input);
          break;
        case "rot18":
          result = rot18(input);
          break;
        case "rot25":
          result = rot25(input);
          break;
        case "vigenere":
          const key = document.getElementById("vigenere-key").value || "KEY";
          result = vigenereDecrypt(input, key);
          break;
        case "playfair":
          const playfairKey =
            document.getElementById("playfair-key").value || "KEYWORD";
          result = playfairDecrypt(input, playfairKey);
          break;
        case "railfence":
          const rails =
            parseInt(document.getElementById("rails-value").value) || 3;
          result = railfenceDecrypt(input, rails);
          break;
        case "scytale":
          const circumference =
            parseInt(document.getElementById("scytale-value").value) || 4;
          result = scytaleDecrypt(input, circumference);
          break;
        case "polybius":
          result = polybiusDecode(input);
          break;
        case "tap":
          result = tapDecode(input);
          break;
        case "book":
          result = bookDecode(input);
          break;
        case "keyboard":
          result = keyboardDecode(input);
          break;
        case "qwerty":
          result = qwertyDecode(input);
          break;
        // Placeholder for unimplemented functions
        default:
          if (
            [
              "dvorak",
              "braille",
              "semaphore",
              "pigpen",
              "templar",
              "runelength",
              "huffman",
              "lz77",
              "mtf",
              "bwt",
              "unicode",
              "utf7",
              "utf8",
              "utf16",
              "utf32",
              "ebcdic",
              "baudot",
              "gray",
              "bcd",
              "excess3",
              "manchester",
              "nrz",
              "rz",
              "ppm",
              "pwm",
              "pcm",
              "delta",
              "fibonacci",
              "factoradic",
              "elias",
              "golomb",
              "rice",
              "shannon",
              "fano",
              "arithmetic",
              "lempel",
              "welch",
              "snappy",
              "lzo",
              "bzip2",
              "gzip",
              "deflate",
              "zlib",
              "xz",
              "lzma",
              "zstd",
              "brotli",
              "pack",
              "compress",
              "zoo",
              "arc",
              "arj",
              "lha",
              "rar",
              "zip",
              "7z",
              "tar",
              "cpio",
              "ar",
              "shar",
              "cab",
              "msi",
              "deb",
              "rpm",
              "dmg",
              "iso",
              "img",
              "bin",
              "cue",
              "nrg",
              "mdf",
              "ccd",
              "vcd",
              "toast",
              "udf",
              "hfs",
              "ntfs",
              "fat",
              "ext",
              "xfs",
              "btrfs",
              "zfs",
              "reiserfs",
              "jfs",
              "minix",
              "cramfs",
              "romfs",
              "squashfs",
              "ubifs",
              "yaffs",
              "jffs",
              "initramfs",
              "overlayfs",
              "aufs",
              "unionfs",
              "tmpfs",
              "sysfs",
              "procfs",
              "devfs",
              "debugfs",
              "securityfs",
              "selinuxfs",
              "smackfs",
              "tomoyo",
              "apparmor",
              "grsecurity",
              "pax",
              "exec-shield",
              "stackguard",
              "propolice",
              "fortify",
              "relro",
              "bind-now",
              "pie",
              "aslr",
              "dep",
              "nx",
              "xd",
              "smep",
              "smap",
              "cet",
              "mbec",
              "kpti",
              "kaiser",
              "meltdown",
              "spectre",
              "zombieload",
              "ridl",
              "fallout",
              "lvi",
              "crosstalk",
              "netcat",
              "platypus",
              "transient",
              "sgaxe",
              "foreshadow",
              "l1tf",
              "spoiler",
              "swapgs",
              "taa",
              "itlb",
              "srbds",
              "mmio",
              "retbleed",
              "hertzbleed",
              "inception",
              "zenbleed",
              "downfall",
              "gather",
              "prefetch",
              "stale",
              "reptar",
              "pacman",
              "ghost",
              "mds",
              "store",
              "vector",
              "data",
              "load",
              "branch",
              "indirect",
              "return",
              "call",
              "jump",
              "conditional",
              "unconditional",
              "direct",
              "near",
              "far",
              "short",
              "long",
              "relative",
              "absolute",
              "displacement",
              "immediate",
              "register",
              "memory",
              "stack",
              "heap",
              "bss",
              "rodata",
              "text",
              "init",
              "fini",
              "plt",
              "got",
              "dynamic",
              "symtab",
              "strtab",
              "shstrtab",
              "hash",
              "gnu",
              "version",
              "verneed",
              "versym",
              "verdef",
              "rel",
              "rela",
              "eh",
              "frame",
              "hdr",
              "gcc",
              "except",
              "table",
              "note",
              "comment",
              "debug",
              "line",
              "info",
              "abbrev",
              "aranges",
              "pubnames",
              "pubtypes",
              "str",
              "loc",
              "macinfo",
              "macro",
              "ranges",
              "types",
              "addr",
              "offsets",
              "loclists",
              "rnglists",
              "gdb",
              "index",
              "names",
              "cu",
              "tu",
              "debuglink",
              "debugaltlink",
              "build",
              "id",
              "go",
              "buildinfo",
              "gosymtab",
              "gopclntab",
              "noptrdata",
              "noptrbss",
              "typelink",
              "itablink",
              "funcdata",
              "gcdata",
              "gcbss",
              "interp",
              "phdr",
              "null",
              "tls",
              "property",
              "sunw",
              "unwind",
              "move",
              "comdat",
              "syminfo",
              "losunw",
              "hisunw",
              "loproc",
              "hiproc",
              "louser",
              "hiuser",
              "file",
              "object",
              "func",
              "section",
              "common",
              "num",
              "ifunc",
              "local",
              "global",
              "weak",
              "loos",
              "hios",
              "undef",
              "abs",
              "xindex",
              "loreserve",
              "hireserve",
              "write",
              "alloc",
              "execinstr",
              "merge",
              "strings",
              "link",
              "order",
              "os",
              "nonconforming",
              "group",
              "compressed",
              "maskos",
              "maskproc",
              "exclude",
              "alpha",
              "gprel",
            ].includes(format)
          ) {
            throw new Error(`Decoding format '${format}' is not implemented`);
          } else {
            throw new Error("Unsupported format");
          }
      }

      resultContainer.innerHTML = result || "No result";
    } catch (error) {
      resultContainer.innerHTML = `<div class="error">Decode failed: ${error.message}</div>`;
    }
  }, 300);
}

// Auto-detect and decode
function autoDetectAndDecode(input) {
  const detections = [];

  if (isBase64(input)) {
    try {
      const decoded = atob(input);
      detections.push(`Base64: ${decoded}`);
    } catch (e) {}
  }

  if (isBase32(input)) {
    try {
      const decoded = base32Decode(input);
      detections.push(`Base32: ${decoded}`);
    } catch (e) {}
  }

  if (isBase85(input)) {
    try {
      const decoded = base85Decode(input);
      detections.push(`Base85: ${decoded}`);
    } catch (e) {}
  }

  if (isBase58(input)) {
    try {
      const decoded = base58Decode(input);
      detections.push(`Base58: ${decoded}`);
    } catch (e) {}
  }

  if (isHex(input)) {
    try {
      const decoded = hexToString(input);
      detections.push(`Hex: ${decoded}`);
    } catch (e) {}
  }

  if (isBinary(input)) {
    try {
      const decoded = binaryToString(input);
      detections.push(`Binary: ${decoded}`);
    } catch (e) {}
  }

  if (isMorse(input)) {
    try {
      const decoded = morseDecode(input);
      detections.push(`Morse: ${decoded}`);
    } catch (e) {}
  }

  if (isUrlEncoded(input)) {
    try {
      const decoded = decodeURIComponent(input);
      detections.push(`URL: ${decoded}`);
    } catch (e) {}
  }

  if (isHtmlEncoded(input)) {
    try {
      const decoded = htmlDecode(input);
      detections.push(`HTML: ${decoded}`);
    } catch (e) {}
  }

  if (isAsciiCodes(input)) {
    try {
      const decoded = asciiToString(input);
      detections.push(`ASCII: ${decoded}`);
    } catch (e) {}
  }

  if (isUuencoded(input)) {
    try {
      const decoded = uuDecode(input);
      detections.push(`UUEncoded: ${decoded}`);
    } catch (e) {}
  }

  if (isQuotedPrintable(input)) {
    try {
      const decoded = quotedPrintableDecode(input);
      detections.push(`Quoted-Printable: ${decoded}`);
    } catch (e) {}
  }

  if (isBraille(input)) {
    try {
      const decoded = brailleDecode(input);
      detections.push(`Braille: ${decoded}`);
    } catch (e) {}
  }

  if (isPolybius(input)) {
    try {
      const decoded = polybiusDecode(input);
      detections.push(`Polybius: ${decoded}`);
    } catch (e) {}
  }

  if (isTap(input)) {
    try {
      const decoded = tapDecode(input);
      detections.push(`Tap Code: ${decoded}`);
    } catch (e) {}
  }

  return detections.length > 0
    ? detections.join("\n\n")
    : "No encoding detected";
}

// Detection functions
function isBase64(str) {
  return /^[A-Za-z0-9+/=]+$/.test(str) && str.length % 4 === 0;
}

function isBase32(str) {
  return /^[A-Z2-7=]+$/.test(str) && str.length % 8 === 0;
}

function isBase85(str) {
  str = str.replace(/\s/g, "");
  if (str.length % 5 !== 0) return false;
  return /^[!-u]*$/.test(str);
}

function isBase58(str) {
  return /^[1-9A-HJ-NP-Za-km-z]+$/.test(str);
}

function isHex(str) {
  return /^[0-9A-Fa-f]+$/.test(str) && str.length % 2 === 0;
}

function isBinary(str) {
  return /^[01\s]+$/.test(str);
}

function isMorse(str) {
  return /^[.-/\s]+$/.test(str);
}

function isUrlEncoded(str) {
  return /%[0-9A-Fa-f]{2}/.test(str);
}

function isHtmlEncoded(str) {
  return /&[a-zA-Z#0-9]+;/.test(str);
}

function isAsciiCodes(str) {
  return /^\d+(\s+\d+)*$/.test(str);
}

function isUuencoded(str) {
  return str.includes("begin ") && str.includes("end");
}

function isQuotedPrintable(str) {
  return /=?[0-9A-F]{2}/.test(str);
}

function isBraille(str) {
  return /^[⠁-⠿\s]+$/.test(str);
}

function isPolybius(str) {
  return /^[1-5]{2}(\s[1-5]{2})*$/.test(str);
}

function isTap(str) {
  return /^[.]{1,5}\s[.]{1,5}(\s[.]{1,5}\s[.]{1,5})*$/.test(str);
}

// Base32 decoding
function base32Decode(str) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  let result = "";

  str = str.replace(/=/g, "");

  for (let i = 0; i < str.length; i++) {
    const char = str[i];
    const index = alphabet.indexOf(char);
    if (index === -1) throw new Error("Invalid base32 character");
    bits += index.toString(2).padStart(5, "0");
  }

  for (let i = 0; i < bits.length; i += 8) {
    const byte = bits.substr(i, 8);
    if (byte.length === 8) {
      result += String.fromCharCode(parseInt(byte, 2));
    }
  }

  return result;
}

// Base85 decoding
function base85Decode(str) {
  const alphabet =
    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz.-:+=^!/*?&<>()[]{}@%$#";
  let result = "";

  str = str.replace(/\s/g, "");

  for (let i = 0; i < str.length; i += 5) {
    const chunk = str.substr(i, 5);
    if (chunk.length === 5) {
      let value = 0;
      for (let j = 0; j < 5; j++) {
        const index = alphabet.indexOf(chunk[j]);
        if (index === -1) throw new Error("Invalid base85 character");
        value = value * 85 + index;
      }

      for (let j = 3; j >= 0; j--) {
        result += String.fromCharCode((value >> (j * 8)) & 0xff);
      }
    }
  }

  return result;
}

// Base58 decoding
function base58Decode(str) {
  const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  let result = [];
  let num = 0;

  for (let i = 0; i < str.length; i++) {
    const char = str[i];
    const index = alphabet.indexOf(char);
    if (index === -1) throw new Error("Invalid base58 character");

    let carry = index;
    for (let j = 0; j < result.length; j++) {
      carry += result[j] * 58;
      result[j] = carry & 0xff;
      carry >>= 8;
    }

    while (carry > 0) {
      result.push(carry & 0xff);
      carry >>= 8;
    }
  }

  let leadingZeros = 0;
  for (let i = 0; i < str.length && str[i] === "1"; i++) {
    leadingZeros++;
  }

  const decoded = new Array(leadingZeros).fill(0).concat(result.reverse());
  return String.fromCharCode(...decoded);
}

// Base36 decoding
function base36Decode(str) {
  const num = parseInt(str, 36);
  if (isNaN(num)) throw new Error("Invalid base36 string");

  let result = "";
  let temp = num;

  while (temp > 0) {
    result = String.fromCharCode(temp & 0xff) + result;
    temp >>= 8;
  }

  return result;
}

// UUEncoding decoding
function uuDecode(str) {
  const lines = str.split("\n");
  let result = "";

  for (let line of lines) {
    if (line.length === 0 || line.startsWith("begin") || line.startsWith("end"))
      continue;

    const length = line.charCodeAt(0) - 32;
    if (length <= 0) continue;

    const data = line.substr(1);
    let decoded = "";

    for (let i = 0; i < data.length; i += 4) {
      const chunk = data.substr(i, 4);
      if (chunk.length < 4) break;

      let value = 0;
      for (let j = 0; j < 4; j++) {
        value = (value << 6) | ((chunk.charCodeAt(j) - 32) & 0x3f);
      }

      for (let j = 2; j >= 0; j--) {
        decoded += String.fromCharCode((value >> (j * 8)) & 0xff);
      }
    }

    result += decoded.substr(0, length);
  }

  return result;
}

// XXEncoding decoding
function xxDecode(str) {
  const alphabet =
    "+-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
  const lines = str.split("\n");
  let result = "";

  for (let line of lines) {
    if (line.length === 0 || line.startsWith("begin") || line.startsWith("end"))
      continue;

    const length = alphabet.indexOf(line[0]);
    if (length < 0) continue;

    const data = line.substr(1);
    let decoded = "";

    for (let i = 0; i < data.length; i += 4) {
      const chunk = data.substr(i, 4);
      if (chunk.length < 4) break;

      let value = 0;
      for (let j = 0; j < 4; j++) {
        const index = alphabet.indexOf(chunk[j]);
        if (index === -1) break;
        value = (value << 6) | index;
      }

      for (let j = 2; j >= 0; j--) {
        decoded += String.fromCharCode((value >> (j * 8)) & 0xff);
      }
    }

    result += decoded.substr(0, length);
  }

  return result;
}

// YEncoding decoding
function yDecode(str) {
  const lines = str.split("\n");
  let result = "";
  let inData = false;

  for (let line of lines) {
    if (line.startsWith("=ybegin")) {
      inData = true;
      continue;
    }
    if (line.startsWith("=yend")) {
      inData = false;
      continue;
    }
    if (!inData) continue;

    let decoded = "";
    let escape = false;

    for (let i = 0; i < line.length; i++) {
      const char = line[i];

      if (char === "=" && !escape) {
        escape = true;
        continue;
      }

      let code = char.charCodeAt(0);
      if (escape) {
        code -= 64;
        escape = false;
      }

      code = (code - 42) & 0xff;
      decoded += String.fromCharCode(code);
    }

    result += decoded;
  }

  return result;
}

// Quoted-Printable decoding
function quotedPrintableDecode(str) {
  return str
    .replace(/=([0-9A-F]{2})/gi, (match, hex) => {
      return String.fromCharCode(parseInt(hex, 16));
    })
    .replace(/=\r?\n/g, "");
}

// Punycode decoding
function punycodeDecode(str) {
  if (!str.startsWith("xn--")) return str;

  const encoded = str.substr(4);
  const base = 36;
  const tMin = 1;
  const tMax = 26;
  const skew = 38;
  const damp = 700;
  const initialBias = 72;
  const initialN = 0x80;

  let output = [];
  let n = initialN;
  let bias = initialBias;
  let i = 0;

  let basicLength = encoded.lastIndexOf("-");
  if (basicLength < 0) basicLength = 0;

  for (let j = 0; j < basicLength; j++) {
    if (encoded.charCodeAt(j) >= 0x80) throw new Error("Invalid punycode");
    output.push(encoded.charCodeAt(j));
  }

  let in_ = basicLength > 0 ? basicLength + 1 : 0;

  while (in_ < encoded.length) {
    let oldi = i;
    let w = 1;
    let k = base;

    while (true) {
      if (in_ >= encoded.length) throw new Error("Invalid punycode");

      let digit = encoded.charCodeAt(in_++);
      if (digit >= 0x30 && digit <= 0x39) digit -= 0x16;
      else if (digit >= 0x41 && digit <= 0x5a) digit -= 0x41;
      else if (digit >= 0x61 && digit <= 0x7a) digit -= 0x61;
      else throw new Error("Invalid punycode");

      i += digit * w;
      let t = k <= bias ? tMin : k >= bias + tMax ? tMax : k - bias;

      if (digit < t) break;

      w *= base - t;
      k += base;
    }

    let out = output.length + 1;
    bias = Math.floor((i - oldi) / (oldi === 0 ? damp : 2));
    n += Math.floor(i / out);
    i %= out;

    output.splice(i++, 0, n);
  }

  return String.fromCharCode(...output);
}

// ROT variations
function rot5(str) {
  return str.replace(/[0-9]/g, (char) => {
    return String.fromCharCode(((char.charCodeAt(0) - 48 + 5) % 10) + 48);
  });
}

function rot13(str) {
  return str.replace(/[a-zA-Z]/g, (char) => {
    const start = char <= "Z" ? 65 : 97;
    return String.fromCharCode(
      ((char.charCodeAt(0) - start + 13) % 26) + start
    );
  });
}

function rot18(str) {
  return rot13(rot5(str));
}

function rot25(str) {
  return str.replace(/[a-zA-Z]/g, (char) => {
    const start = char <= "Z" ? 65 : 97;
    return String.fromCharCode(
      ((char.charCodeAt(0) - start + 25) % 26) + start
    );
  });
}

function rot47(str) {
  return str.replace(/[!-~]/g, (char) => {
    return String.fromCharCode(((char.charCodeAt(0) - 33 + 47) % 94) + 33);
  });
}

// Caesar cipher
function caesarCipher(str, shift) {
  return str.replace(/[a-zA-Z]/g, (char) => {
    const start = char <= "Z" ? 65 : 97;
    return String.fromCharCode(
      ((char.charCodeAt(0) - start + shift + 26) % 26) + start
    );
  });
}

// Atbash cipher
function atbashCipher(str) {
  return str.replace(/[a-zA-Z]/g, (char) => {
    const start = char <= "Z" ? 65 : 97;
    return String.fromCharCode(25 - (char.charCodeAt(0) - start) + start);
  });
}

// Vigenère cipher
function vigenereDecrypt(str, key) {
  let result = "";
  let keyIndex = 0;

  for (let i = 0; i < str.length; i++) {
    const char = str[i];

    if (/[a-zA-Z]/.test(char)) {
      const start = char <= "Z" ? 65 : 97;
      const keyChar = key[keyIndex % key.length].toLowerCase();
      const keyShift = keyChar.charCodeAt(0) - 97;

      const decrypted =
        ((char.charCodeAt(0) - start - keyShift + 26) % 26) + start;
      result += String.fromCharCode(decrypted);
      keyIndex++;
    } else {
      result += char;
    }
  }

  return result;
}

// Playfair cipher
function playfairDecrypt(str, key) {
  const alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ";
  const grid = [];
  let usedChars = new Set();

  for (let char of key.toUpperCase()) {
    if (char === "J") char = "I";
    if (alphabet.includes(char) && !usedChars.has(char)) {
      grid.push(char);
      usedChars.add(char);
    }
  }

  for (let char of alphabet) {
    if (!usedChars.has(char)) {
      grid.push(char);
    }
  }

  const pos = {};
  for (let i = 0; i < 25; i++) {
    pos[grid[i]] = { row: Math.floor(i / 5), col: i % 5 };
  }

  str = str.toUpperCase().replace(/[^A-Z]/g, "");
  let result = "";

  for (let i = 0; i < str.length; i += 2) {
    let a = str[i];
    let b = str[i + 1] || "X";

    if (a === "J") a = "I";
    if (b === "J") b = "I";

    const posA = pos[a];
    const posB = pos[b];

    if (posA.row === posB.row) {
      result += grid[posA.row * 5 + ((posA.col + 4) % 5)];
      result += grid[posB.row * 5 + ((posB.col + 4) % 5)];
    } else if (posA.col === posB.col) {
      result += grid[((posA.row + 4) % 5) * 5 + posA.col];
      result += grid[((posB.row + 4) % 5) * 5 + posB.col];
    } else {
      result += grid[posA.row * 5 + posB.col];
      result += grid[posB.row * 5 + posA.col];
    }
  }

  return result;
}

// Rail fence cipher
function railfenceDecrypt(str, rails) {
  if (rails === 1) return str;

  const fence = Array(rails)
    .fill()
    .map(() => []);
  let rail = 0;
  let direction = 1;

  for (let i = 0; i < str.length; i++) {
    fence[rail].push(i);
    rail += direction;

    if (rail === rails - 1 || rail === 0) {
      direction = -direction;
    }
  }

  let index = 0;
  for (let i = 0; i < rails; i++) {
    for (let j = 0; j < fence[i].length; j++) {
      fence[i][j] = str[index++];
    }
  }

  let result = "";
  rail = 0;
  direction = 1;
  const railIndex = Array(rails).fill(0);

  for (let i = 0; i < str.length; i++) {
    result += fence[rail][railIndex[rail]++];
    rail += direction;

    if (rail === rails - 1 || rail === 0) {
      direction = -direction;
    }
  }

  return result;
}

// Scytale cipher
function scytaleDecrypt(str, circumference) {
  const rows = Math.ceil(str.length / circumference);
  const grid = Array(rows)
    .fill()
    .map(() => Array(circumference).fill(""));

  let index = 0;
  for (let col = 0; col < circumference; col++) {
    for (let row = 0; row < rows; row++) {
      if (index < str.length) {
        grid[row][col] = str[index++];
      }
    }
  }

  let result = "";
  for (let row = 0; row < rows; row++) {
    result += grid[row].join("");
  }

  return result.replace(/\s+$/, "");
}

// Hex to string
function hexToString(hex) {
  let result = "";
  for (let i = 0; i < hex.length; i += 2) {
    result += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
  }
  return result;
}

// Binary to string
function binaryToString(binary) {
  const bytes = binary.split(/\s+/);
  return bytes.map((byte) => String.fromCharCode(parseInt(byte, 2))).join("");
}

// Octal to string
function octalToString(octal) {
  const codes = octal.split(/\s+/);
  return codes.map((code) => String.fromCharCode(parseInt(code, 8))).join("");
}

// HTML decoding
function htmlDecode(str) {
  return str
    .replace(/&/g, "&")
    .replace(/</g, "<")
    .replace(/>/g, ">")
    .replace(/"/g, '"')
    .replace(/'/g, "'")
    .replace(/ /g, " ")
    .replace(/&#(\d+);/g, (match, dec) => String.fromCharCode(dec))
    .replace(/&#x([0-9a-f]+);/gi, (match, hex) =>
      String.fromCharCode(parseInt(hex, 16))
    );
}

// XML decoding
function xmlDecode(str) {
  return str
    .replace(/&/g, "&")
    .replace(/</g, "<")
    .replace(/>/g, ">")
    .replace(/"/g, '"')
    .replace(/'/g, "'");
}

// Morse decoding
function morseDecode(str) {
  const morseMap = {
    ".-": "A",
    "-...": "B",
    "-.-.": "C",
    "-..": "D",
    ".": "E",
    "..-.": "F",
    "--.": "G",
    "....": "H",
    "..": "I",
    ".---": "J",
    "-.-": "K",
    ".-..": "L",
    "--": "M",
    "-.": "N",
    "---": "O",
    ".--.": "P",
    "--.-": "Q",
    ".-.": "R",
    "...": "S",
    "-": "T",
    "..-": "U",
    "...-": "V",
    ".--": "W",
    "-..-": "X",
    "-.--": "Y",
    "--..": "Z",
    "-----": "0",
    ".----": "1",
    "..---": "2",
    "...--": "3",
    "....-": "4",
    ".....": "5",
    "-....": "6",
    "--...": "7",
    "---..": "8",
    "----.": "9",
    "/": " ",
    "..--..": "?",
    ".-.-.-": ".",
    "--..--": ",",
    "-.-.--": "!",
    ".--.-.": "@",
    "---...": ":",
    "-.-.-.": ";",
    "-..-.": "/",
    "-....-": "-",
    "..--.-": "_",
    "-.--.": "(",
    "-.--.-": ")",
    ".-.-.": "+",
    "-...-": "=",
    "...-..-": "$",
    ".--.-": "Å",
    ".-.-": "Ä",
    "---.": "Ö",
    "..--": "Ü",
    ".---.": "É",
    "-.-.": "Ñ",
  };

  return str
    .split(" ")
    .map((char) => morseMap[char] || char)
    .join("");
}

// Bacon decoding
function baconDecode(str) {
  const baconMap = {
    AAAAA: "A",
    AAAAB: "B",
    AAABA: "C",
    AAABB: "D",
    AABAA: "E",
    AABAB: "F",
    AABBA: "G",
    AABBB: "H",
    ABAAA: "I",
    ABAAB: "J",
    ABABA: "K",
    ABABB: "L",
    ABBAA: "M",
    ABBAB: "N",
    ABBBA: "O",
    ABBBB: "P",
    BAAAA: "Q",
    BAAAB: "R",
    BAABA: "S",
    BAABB: "T",
    BABAA: "U",
    BABAB: "V",
    BABBA: "W",
    BABBB: "X",
    BBAAA: "Y",
    BBAAB: "Z",
  };

  let result = "";
  for (let i = 0; i < str.length; i += 5) {
    const chunk = str.substr(i, 5);
    if (chunk.length === 5) {
      result += baconMap[chunk] || chunk;
    }
  }
  return result;
}

// ASCII codes to string
function asciiToString(str) {
  const codes = str.split(/\s+/);
  return codes.map((code) => String.fromCharCode(parseInt(code))).join("");
}

// Phonetic decoding
function phoneticDecode(str) {
  const phoneticMap = {
    Alpha: "A",
    Bravo: "B",
    Charlie: "C",
    Delta: "D",
    Echo: "E",
    Foxtrot: "F",
    Golf: "G",
    Hotel: "H",
    India: "I",
    Juliet: "J",
    Kilo: "K",
    Lima: "L",
    Mike: "M",
    November: "N",
    Oscar: "O",
    Papa: "P",
    Quebec: "Q",
    Romeo: "R",
    Sierra: "S",
    Tango: "T",
    Uniform: "U",
    Victor: "V",
    Whiskey: "W",
    "X-ray": "X",
    Yankee: "Y",
    Zulu: "Z",
  };

  return str
    .split(" ")
    .map((word) => phoneticMap[word] || word)
    .join("");
}

// Polybius square
function polybiusDecode(str) {
  const polybiusMap = {
    11: "A",
    12: "B",
    13: "C",
    14: "D",
    15: "E",
    21: "F",
    22: "G",
    23: "H",
    24: "I",
    25: "J",
    31: "K",
    32: "L",
    33: "M",
    34: "N",
    35: "O",
    41: "P",
    42: "Q",
    43: "R",
    44: "S",
    45: "T",
    51: "U",
    52: "V",
    53: "W",
    54: "X",
    55: "Y",
  };

  let result = "";
  const pairs = str.match(/\d{2}/g) || [];

  for (let pair of pairs) {
    result += polybiusMap[pair] || pair;
  }

  return result;
}

// Tap code
function tapDecode(str) {
  const tapMap = {
    11: "A",
    12: "B",
    13: "C",
    14: "D",
    15: "E",
    21: "F",
    22: "G",
    23: "H",
    24: "I",
    25: "J",
    31: "K",
    32: "L",
    33: "M",
    34: "N",
    35: "O",
    41: "P",
    42: "Q",
    43: "R",
    44: "S",
    45: "T",
    51: "U",
    52: "V",
    53: "W",
    54: "X",
    55: "Y",
  };

  const converted = str.replace(/\s+/g, " ").split(" ");
  let result = "";

  for (let i = 0; i < converted.length; i += 2) {
    if (i + 1 < converted.length) {
      const row = converted[i].length;
      const col = converted[i + 1].length;
      const code = row.toString() + col.toString();
      result += tapMap[code] || code;
    }
  }

  return result;
}

// Book cipher placeholder
function bookDecode(str) {
  return "Book cipher requires reference text";
}

// Keyboard shift
function keyboardDecode(str) {
  const shiftMap = {
    Q: "A",
    W: "S",
    E: "D",
    R: "F",
    T: "G",
    Y: "H",
    U: "J",
    I: "K",
    O: "L",
    P: "M",
    A: "Z",
    S: "X",
    D: "C",
    F: "V",
    G: "B",
    H: "N",
    J: "M",
    K: "L",
    L: "O",
    Z: "Q",
    X: "W",
    C: "E",
    V: "R",
    B: "T",
    N: "Y",
    M: "U",
  };

  return str
    .toUpperCase()
    .split("")
    .map((char) => shiftMap[char] || char)
    .join("");
}

// QWERTY decode
function qwertyDecode(str) {
  const qwertyMap = {
    Q: "A",
    W: "S",
    E: "D",
    R: "F",
    T: "G",
    Y: "H",
    U: "J",
    I: "K",
    O: "L",
    P: ";",
    A: "Z",
    S: "X",
    D: "C",
    F: "V",
    G: "B",
    H: "N",
    J: "M",
    K: ",",
    L: ".",
    Z: "Q",
    X: "W",
    C: "E",
    V: "R",
    B: "T",
    N: "Y",
    M: "U",
    ",": "I",
    ".": "O",
    ";": "P",
  };

  return str
    .toUpperCase()
    .split("")
    .map((char) => qwertyMap[char] || char)
    .join("");
}

// Placeholder for unimplemented functions
function placeholderDecode(str) {
  throw new Error("This decoding format is not implemented");
}

// Assign placeholder to unimplemented functions
const unimplemented = placeholderDecode;
const [
  dvorakDecode,
  brailleDecode,
  semaphoreDecode,
  pigpenDecode,
  templarDecode,
  runLengthDecode,
  huffmanDecode,
  lz77Decode,
  mtfDecode,
  bwtDecode,
  unicodeDecode,
  utf7Decode,
  utf8Decode,
  utf16Decode,
  utf32Decode,
  ebcdicDecode,
  baudotDecode,
  grayDecode,
  bcdDecode,
  excess3Decode,
  manchesterDecode,
  nrzDecode,
  rzDecode,
  ppmDecode,
  pwmDecode,
  pcmDecode,
  deltaDecode,
  fibonacciDecode,
  factoradicDecode,
  eliasDecode,
  golombDecode,
  riceDecode,
  shannonDecode,
  fanoDecode,
  arithmeticDecode,
  lempelDecode,
  welchDecode,
  snappyDecode,
  lzoDecode,
  bzip2Decode,
  gzipDecode,
  deflateDecode,
  zlibDecode,
  xzDecode,
  lzmaDecode,
  zstdDecode,
  brotliDecode,
  packDecode,
  compressDecode,
  zooDecode,
  arcDecode,
  arjDecode,
  lhaDecode,
  rarDecode,
  zipDecode,
  sevenZipDecode,
  tarDecode,
  cpioDecode,
  arDecode,
  sharDecode,
  cabDecode,
  msiDecode,
  debDecode,
  rpmDecode,
  dmgDecode,
  isoDecode,
  imgDecode,
  binDecode,
  cueDecode,
  nrgDecode,
  mdfDecode,
  ccdDecode,
  vcdDecode,
  toastDecode,
  udfDecode,
  hfsDecode,
  ntfsDecode,
  fatDecode,
  extDecode,
  xfsDecode,
  btrfsDecode,
  zfsDecode,
  reiserfsDecode,
  jfsDecode,
  minixDecode,
  cramfsDecode,
  romfsDecode,
  squashfsDecode,
  ubifsDecode,
  yaffsDecode,
  jffsDecode,
  initramfsDecode,
  overlayfsDecode,
  aufsDecode,
  unionfsDecode,
  tmpfsDecode,
  sysfsDecode,
  procfsDecode,
  devfsDecode,
  debugfsDecode,
  securityfsDecode,
  selinuxfsDecode,
  smackfsDecode,
  tomoyoDecode,
  apparmorDecode,
  grsecurityDecode,
  paxDecode,
  execShieldDecode,
  stackguardDecode,
  propoliceDecode,
  fortifyDecode,
  relroDecode,
  bindNowDecode,
  pieDecode,
  aslrDecode,
  depDecode,
  nxDecode,
  xdDecode,
  smepDecode,
  smapDecode,
  cetDecode,
  mbecDecode,
  kptiDecode,
  kaiserDecode,
  meltdownDecode,
  spectreDecode,
  zombieloadDecode,
  ridlDecode,
  falloutDecode,
  lviDecode,
  crosstalkDecode,
  netcatDecode,
  platypusDecode,
  transientDecode,
  sgaxeDecode,
  foreshadowDecode,
  l1tfDecode,
  spoilerDecode,
  swapgsDecode,
  taaDecode,
  itlbDecode,
  srbdsDecode,
  mmioDecode,
  retbleedDecode,
  hertzbleedDecode,
  inceptionDecode,
  zenbleedDecode,
  downfallDecode,
  gatherDecode,
  prefetchDecode,
  staleDecode,
  reptarDecode,
  pacmanDecode,
  ghostDecode,
  mdsDecode,
  storeDecode,
  vectorDecode,
  dataDecode,
  loadDecode,
  branchDecode,
  indirectDecode,
  returnDecode,
  callDecode,
  jumpDecode,
  conditionalDecode,
  unconditionalDecode,
  directDecode,
  nearDecode,
  farDecode,
  shortDecode,
  longDecode,
  relativeDecode,
  absoluteDecode,
  displacementDecode,
  immediateDecode,
  registerDecode,
  memoryDecode,
  stackDecode,
  heapDecode,
  bssDecode,
  rodataDecode,
  textDecode,
  initDecode,
  finiDecode,
  pltDecode,
  gotDecode,
  dynamicDecode,
  symtabDecode,
  strtabDecode,
  shstrtabDecode,
  hashDecode,
  gnuDecode,
  versionDecode,
  verneedDecode,
  versymDecode,
  verdefDecode,
  relDecode,
  relaDecode,
  ehDecode,
  frameDecode,
  hdrDecode,
  gccDecode,
  exceptDecode,
  tableDecode,
  noteDecode,
  commentDecode,
  debugDecode,
  lineDecode,
  infoDecode,
  abbrevDecode,
  arangesDecode,
  pubnamesDecode,
  pubtypesDecode,
  strDecode,
  locDecode,
  macinfoDecode,
  macroDecode,
  rangesDecode,
  typesDecode,
  addrDecode,
  offsetsDecode,
  loclistsDecode,
  rnglistsDecode,
  gdbDecode,
  indexDecode,
  namesDecode,
  cuDecode,
  tuDecode,
  debuglinkDecode,
  debugaltlinkDecode,
  buildDecode,
  idDecode,
  goDecode,
  buildinfoDecode,
  gosymtabDecode,
  gopclntabDecode,
  noptrdataDecode,
  noptrbssDecode,
  typelinkDecode,
  itablinkDecode,
  funcdataDecode,
  gcdataDecode,
  gcbssDecode,
  interpDecode,
  phdrDecode,
  nullDecode,
  tlsDecode,
  propertyDecode,
  sunwDecode,
  unwindDecode,
  moveDecode,
  comdatDecode,
  syminfoDecode,
  losunwDecode,
  hisunwDecode,
  louserDecode,
  hiuserDecode,
  fileDecode,
  objectDecode,
  funcDecode,
  sectionDecode,
  commonDecode,
  numDecode,
  ifuncDecode,
  localDecode,
  globalDecode,
  weakDecode,
  loosDecode,
  hiosDecode,
  undefDecode,
  absDecode,
  xindexDecode,
  loreserveDecode,
  hireserveDecode,
  writeDecode,
  allocDecode,
  execinstrDecode,
  mergeDecode,
  stringsDecode,
  linkDecode,
  orderDecode,
  osDecode,
  nonconformingDecode,
  groupDecode,
  compressedDecode,
  maskosDecode,
  maskprocDecode,
  excludeDecode,
  alphaDecode,
  gprelDecode,
] = Array(168).fill(unimplemented);

// Placeholder for showLoading
function showLoading(containerId) {
  document.getElementById(containerId).innerHTML = "<div>Loading...</div>";
}
