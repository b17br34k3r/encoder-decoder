function hashText() {
  const input = document.getElementById("hash-input").value;
  const resultsContainer = document.getElementById("hash-results");

  if (!input.trim()) {
    resultsContainer.innerHTML =
      '<div class="error">Please enter text to hash</div>';
    return;
  }

  showLoading("hash-results");

  setTimeout(async () => {
    clearResults("hash-results");

    try {
      // Cryptographic hash functions

      resultsContainer.appendChild(
        createResultItem("SHA-1", await sha1(input))
      );
      resultsContainer.appendChild(
        createResultItem("SHA-256", await sha256(input))
      );
      resultsContainer.appendChild(
        createResultItem("SHA-384", await sha384(input))
      );
      resultsContainer.appendChild(
        createResultItem("SHA-512", await sha512(input))
      );

      // Non-cryptographic hash functions
      resultsContainer.appendChild(createResultItem("djb2", djb2Hash(input)));
      resultsContainer.appendChild(createResultItem("djb2a", djb2aHash(input)));
      resultsContainer.appendChild(createResultItem("SDBM", sdbmHash(input)));
      resultsContainer.appendChild(
        createResultItem("FNV-1a (32-bit)", fnv1aHash(input))
      );
      resultsContainer.appendChild(
        createResultItem("FNV-1a (64-bit)", fnv1a64Hash(input))
      );
      resultsContainer.appendChild(
        createResultItem("FNV-1 (32-bit)", fnv1Hash(input))
      );
      resultsContainer.appendChild(
        createResultItem("Simple Hash", simpleHash(input))
      );

      // Additional hash functions
      resultsContainer.appendChild(
        createResultItem("Java hashCode", javaHashCode(input))
      );
      resultsContainer.appendChild(
        createResultItem("Adler-32", adler32Hash(input))
      );
      resultsContainer.appendChild(
        createResultItem("CRC-32", crc32Hash(input))
      );
      resultsContainer.appendChild(
        createResultItem("ELF Hash", elfHash(input))
      );
      resultsContainer.appendChild(
        createResultItem("BKDR Hash", bkdrHash(input))
      );
      resultsContainer.appendChild(createResultItem("AP Hash", apHash(input)));
      resultsContainer.appendChild(createResultItem("JS Hash", jsHash(input)));
      resultsContainer.appendChild(createResultItem("RS Hash", rsHash(input)));
      resultsContainer.appendChild(
        createResultItem("DEK Hash", dekHash(input))
      );
      resultsContainer.appendChild(
        createResultItem("PJW Hash", pjwHash(input))
      );
      resultsContainer.appendChild(
        createResultItem("BUZ Hash", buzHash(input))
      );
      resultsContainer.appendChild(
        createResultItem("DJB Hash", djbHash(input))
      );
      resultsContainer.appendChild(
        createResultItem("LOSE Hash", loseHash(input))
      );
      resultsContainer.appendChild(
        createResultItem("Bernstein Hash", bernsteinHash(input))
      );
      resultsContainer.appendChild(
        createResultItem("Shift-Add-XOR", shiftAddXorHash(input))
      );
      resultsContainer.appendChild(
        createResultItem("Rotating Hash", rotatingHash(input))
      );
      resultsContainer.appendChild(
        createResultItem("One-at-a-Time", oneAtATimeHash(input))
      );
      resultsContainer.appendChild(
        createResultItem("Murmur Hash v2", murmurHash2(input))
      );
      resultsContainer.appendChild(
        createResultItem("Murmur Hash v3", murmurHash3(input))
      );
      resultsContainer.appendChild(
        createResultItem("CityHash", cityHash(input))
      );
      resultsContainer.appendChild(
        createResultItem("FarmHash", farmHash(input))
      );
      resultsContainer.appendChild(
        createResultItem("Pearson Hash", pearsonHash(input))
      );
      resultsContainer.appendChild(
        createResultItem("Fletcher-16", fletcher16Hash(input))
      );
      resultsContainer.appendChild(
        createResultItem("Fletcher-32", fletcher32Hash(input))
      );
      resultsContainer.appendChild(
        createResultItem("Lookup3", lookup3Hash(input))
      );
      resultsContainer.appendChild(
        createResultItem("SuperFastHash", superFastHash(input))
      );
      resultsContainer.appendChild(
        createResultItem("MaPrime2c", maPrime2cHash(input))
      );
      resultsContainer.appendChild(
        createResultItem("SpookyHash", spookyHash(input))
      );
      resultsContainer.appendChild(
        createResultItem("Paul Hsieh Hash", paulHsiehHash(input))
      );
      resultsContainer.appendChild(
        createResultItem("Bob Jenkins Hash", bobJenkinsHash(input))
      );
      resultsContainer.appendChild(
        createResultItem("Thomas Wang Hash", thomasWangHash(input))
      );
      resultsContainer.appendChild(
        createResultItem("Knuth Hash", knuthHash(input))
      );
    } catch (error) {
      resultsContainer.innerHTML = `<div class="error">Hashing error: ${error.message}</div>`;
    }
  }, 300);
}

async function sha1(input) {
  const encoder = new TextEncoder();
  const data = encoder.encode(input);
  const hashBuffer = await crypto.subtle.digest("SHA-1", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function sha256(input) {
  const encoder = new TextEncoder();
  const data = encoder.encode(input);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function sha384(input) {
  const encoder = new TextEncoder();
  const data = encoder.encode(input);
  const hashBuffer = await crypto.subtle.digest("SHA-384", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function sha512(input) {
  const encoder = new TextEncoder();
  const data = encoder.encode(input);
  const hashBuffer = await crypto.subtle.digest("SHA-512", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
}

// Non-cryptographic hash functions
function djb2Hash(input) {
  let hash = 5381;
  for (let i = 0; i < input.length; i++) {
    hash = (hash << 5) + hash + input.charCodeAt(i);
  }
  return (hash >>> 0).toString(16);
}

function djb2aHash(input) {
  let hash = 5381;
  for (let i = 0; i < input.length; i++) {
    hash = ((hash << 5) + hash) ^ input.charCodeAt(i);
  }
  return (hash >>> 0).toString(16);
}

function sdbmHash(input) {
  let hash = 0;
  for (let i = 0; i < input.length; i++) {
    hash = input.charCodeAt(i) + (hash << 6) + (hash << 16) - hash;
  }
  return (hash >>> 0).toString(16);
}

function fnv1aHash(input) {
  let hash = 2166136261;
  for (let i = 0; i < input.length; i++) {
    hash ^= input.charCodeAt(i);
    hash *= 16777619;
  }
  return (hash >>> 0).toString(16);
}

function fnv1a64Hash(input) {
  let hash = BigInt("14695981039346656037");
  const fnvPrime = BigInt("1099511628211");
  for (let i = 0; i < input.length; i++) {
    hash ^= BigInt(input.charCodeAt(i));
    hash *= fnvPrime;
  }
  return (hash & BigInt("0xFFFFFFFFFFFFFFFF")).toString(16);
}

function fnv1Hash(input) {
  let hash = 2166136261;
  for (let i = 0; i < input.length; i++) {
    hash *= 16777619;
    hash ^= input.charCodeAt(i);
  }
  return (hash >>> 0).toString(16);
}

function simpleHash(input) {
  let hash = 0;
  if (input.length === 0) return hash.toString(16);
  for (let i = 0; i < input.length; i++) {
    const char = input.charCodeAt(i);
    hash = (hash << 5) - hash + char;
    hash = hash & hash;
  }
  return Math.abs(hash).toString(16);
}

function javaHashCode(input) {
  let hash = 0;
  for (let i = 0; i < input.length; i++) {
    hash = (hash << 5) - hash + input.charCodeAt(i);
    hash = hash & hash;
  }
  return hash.toString(16);
}

function adler32Hash(input) {
  let a = 1,
    b = 0;
  for (let i = 0; i < input.length; i++) {
    a = (a + input.charCodeAt(i)) % 65521;
    b = (b + a) % 65521;
  }
  return ((b << 16) | a).toString(16);
}

function crc32Hash(input) {
  const crcTable = [];
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let j = 0; j < 8; j++) {
      c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    crcTable[i] = c;
  }

  let crc = 0 ^ -1;
  for (let i = 0; i < input.length; i++) {
    crc = (crc >>> 8) ^ crcTable[(crc ^ input.charCodeAt(i)) & 0xff];
  }
  return ((crc ^ -1) >>> 0).toString(16);
}

function elfHash(input) {
  let hash = 0;
  for (let i = 0; i < input.length; i++) {
    hash = (hash << 4) + input.charCodeAt(i);
    let x = hash & 0xf0000000;
    if (x !== 0) {
      hash ^= x >>> 24;
    }
    hash &= ~x;
  }
  return (hash >>> 0).toString(16);
}

function bkdrHash(input) {
  let hash = 0;
  const seed = 131;
  for (let i = 0; i < input.length; i++) {
    hash = (hash * seed + input.charCodeAt(i)) & 0xffffffff;
  }
  return (hash >>> 0).toString(16);
}

function apHash(input) {
  let hash = 0xaaaaaaaa;
  for (let i = 0; i < input.length; i++) {
    hash ^=
      (i & 1) === 0
        ? (hash << 7) ^ (input.charCodeAt(i) * (hash >>> 3))
        : ~(((hash << 11) + input.charCodeAt(i)) ^ (hash >>> 5));
  }
  return (hash >>> 0).toString(16);
}

function jsHash(input) {
  let hash = 1315423911;
  for (let i = 0; i < input.length; i++) {
    hash ^= (hash << 5) + input.charCodeAt(i) + (hash >>> 2);
  }
  return (hash >>> 0).toString(16);
}

function rsHash(input) {
  let hash = 0;
  const a = 378551;
  const b = 63689;
  for (let i = 0; i < input.length; i++) {
    hash = hash * a + input.charCodeAt(i);
    hash = hash & 0xffffffff;
  }
  return (hash >>> 0).toString(16);
}

function dekHash(input) {
  let hash = input.length;
  for (let i = 0; i < input.length; i++) {
    hash = (hash << 5) ^ (hash >>> 27) ^ input.charCodeAt(i);
  }
  return (hash >>> 0).toString(16);
}

function pjwHash(input) {
  let hash = 0;
  for (let i = 0; i < input.length; i++) {
    hash = (hash << 4) + input.charCodeAt(i);
    let g = hash & 0xf0000000;
    if (g !== 0) {
      hash ^= g >>> 24;
      hash ^= g;
    }
  }
  return (hash >>> 0).toString(16);
}

function buzHash(input) {
  let hash = 0;
  for (let i = 0; i < input.length; i++) {
    hash = (hash << 1) + input.charCodeAt(i);
  }
  return (hash >>> 0).toString(16);
}

function djbHash(input) {
  let hash = 5381;
  for (let i = 0; i < input.length; i++) {
    hash = (hash << 5) + hash + input.charCodeAt(i);
  }
  return (hash >>> 0).toString(16);
}

function loseHash(input) {
  let hash = 0;
  for (let i = 0; i < input.length; i++) {
    hash += input.charCodeAt(i);
  }
  return (hash >>> 0).toString(16);
}

function bernsteinHash(input) {
  let hash = 5381;
  for (let i = 0; i < input.length; i++) {
    hash = hash * 33 + input.charCodeAt(i);
  }
  return (hash >>> 0).toString(16);
}

function shiftAddXorHash(input) {
  let hash = 0;
  for (let i = 0; i < input.length; i++) {
    hash ^= (hash << 5) + (hash >>> 2) + input.charCodeAt(i);
  }
  return (hash >>> 0).toString(16);
}

function rotatingHash(input) {
  let hash = 0;
  for (let i = 0; i < input.length; i++) {
    hash = (hash << 4) ^ (hash >>> 28) ^ input.charCodeAt(i);
  }
  return (hash >>> 0).toString(16);
}

function oneAtATimeHash(input) {
  let hash = 0;
  for (let i = 0; i < input.length; i++) {
    hash += input.charCodeAt(i);
    hash += hash << 10;
    hash ^= hash >>> 6;
  }
  hash += hash << 3;
  hash ^= hash >>> 11;
  hash += hash << 15;
  return (hash >>> 0).toString(16);
}

function murmurHash2(input) {
  const seed = 0x9747b28c;
  const m = 0x5bd1e995;
  const r = 24;
  let h = seed ^ input.length;

  for (let i = 0; i < input.length; i++) {
    let k = input.charCodeAt(i);
    k = (k * m) & 0xffffffff;
    k ^= k >>> r;
    k = (k * m) & 0xffffffff;
    h = (h * m) & 0xffffffff;
    h ^= k;
  }

  h ^= h >>> 13;
  h = (h * m) & 0xffffffff;
  h ^= h >>> 15;

  return (h >>> 0).toString(16);
}

function murmurHash3(input) {
  const seed = 0x9747b28c;
  const c1 = 0xcc9e2d51;
  const c2 = 0x1b873593;
  const r1 = 15;
  const r2 = 13;
  const m = 5;
  const n = 0xe6546b64;

  let hash = seed;

  for (let i = 0; i < input.length; i++) {
    let k = input.charCodeAt(i);
    k = (k * c1) & 0xffffffff;
    k = (k << r1) | (k >>> (32 - r1));
    k = (k * c2) & 0xffffffff;

    hash ^= k;
    hash = (hash << r2) | (hash >>> (32 - r2));
    hash = (hash * m + n) & 0xffffffff;
  }

  hash ^= input.length;
  hash ^= hash >>> 16;
  hash = (hash * 0x85ebca6b) & 0xffffffff;
  hash ^= hash >>> 13;
  hash = (hash * 0xc2b2ae35) & 0xffffffff;
  hash ^= hash >>> 16;

  return (hash >>> 0).toString(16);
}

function xxHash(input) {
  const PRIME32_1 = 0x9e3779b1;
  const PRIME32_2 = 0x85ebca77;
  const PRIME32_3 = 0xc2b2ae3d;
  const PRIME32_4 = 0x27d4eb2f;
  const PRIME32_5 = 0x165667b1;

  let h32 = (0x9747b28c + input.length + PRIME32_5) & 0xffffffff;

  for (let i = 0; i < input.length; i++) {
    h32 = (h32 + input.charCodeAt(i) * PRIME32_5) & 0xffffffff;
    h32 = ((h32 << 11) | (h32 >>> 21)) & 0xffffffff;
    h32 = (h32 * PRIME32_1) & 0xffffffff;
  }

  h32 ^= h32 >>> 15;
  h32 = (h32 * PRIME32_2) & 0xffffffff;
  h32 ^= h32 >>> 13;
  h32 = (h32 * PRIME32_3) & 0xffffffff;
  h32 ^= h32 >>> 16;

  return (h32 >>> 0).toString(16);
}

function cityHash(input) {
  let hash = 0;
  for (let i = 0; i < input.length; i++) {
    hash = hash * 37 + input.charCodeAt(i);
  }
  return (hash >>> 0).toString(16);
}

function farmHash(input) {
  let hash = 0;
  for (let i = 0; i < input.length; i++) {
    hash = ((hash << 5) - hash + input.charCodeAt(i)) & 0xffffffff;
  }
  return (hash >>> 0).toString(16);
}

function pearsonHash(input) {
  const T = [
    251, 175, 119, 215, 81, 14, 79, 191, 103, 49, 181, 143, 186, 157, 0, 232,
    31, 32, 55, 60, 152, 58, 17, 237, 174, 70, 160, 144, 220, 90, 57, 223, 59,
    3, 18, 140, 111, 166, 203, 196, 134, 243, 124, 95, 222, 179, 197, 65, 180,
    48, 36, 15, 107, 46, 233, 130, 165, 30, 123, 161, 209, 23, 97, 16, 40, 91,
    219, 61, 100, 10, 210, 109, 250, 127, 22, 138, 29, 108, 244, 67, 207, 9,
    178, 204, 74, 98, 126, 249, 167, 116, 34, 77, 193, 200, 121, 5, 20, 113, 71,
    35, 128, 13, 182, 94, 25, 226, 227, 199, 75, 27, 41, 245, 230, 224, 43, 225,
    177, 26, 155, 150, 212, 142, 218, 115, 241, 73, 88, 105, 39, 114, 62, 255,
    192, 201, 145, 214, 168, 158, 221, 148, 154, 122, 12, 84, 82, 163, 44, 139,
    228, 236, 205, 242, 217, 11, 187, 146, 159, 64, 86, 239, 195, 42, 106, 198,
    118, 112, 184, 172, 87, 2, 173, 117, 176, 229, 247, 253, 137, 185, 99, 164,
    102, 147, 45, 66, 231, 52, 141, 211, 194, 206, 246, 238, 56, 110, 78, 248,
    63, 240, 189, 93, 92, 51, 53, 183, 19, 171, 72, 50, 33, 104, 101, 69, 8,
    252, 83, 120, 76, 54, 85, 220, 24, 96, 68, 156, 6, 47, 130, 188, 208, 170,
    234, 190, 216, 235, 7, 213, 1, 37, 38, 21, 28, 80, 4, 169, 133, 129, 135,
    151, 131, 162, 132, 149, 136, 153, 125, 125, 153, 59, 174, 12, 89, 103, 211,
    63, 136, 153, 153, 153, 153, 153, 153, 153, 153, 153, 153, 153, 153, 153,
  ];

  let hash = 0;
  for (let i = 0; i < input.length; i++) {
    hash = T[hash ^ input.charCodeAt(i)];
  }
  return hash.toString(16);
}

function fletcher16Hash(input) {
  let sum1 = 0,
    sum2 = 0;
  for (let i = 0; i < input.length; i++) {
    sum1 = (sum1 + input.charCodeAt(i)) % 255;
    sum2 = (sum2 + sum1) % 255;
  }
  return ((sum2 << 8) | sum1).toString(16);
}

function fletcher32Hash(input) {
  let sum1 = 0,
    sum2 = 0;
  for (let i = 0; i < input.length; i++) {
    sum1 = (sum1 + input.charCodeAt(i)) % 65535;
    sum2 = (sum2 + sum1) % 65535;
  }
  return ((sum2 << 16) | sum1).toString(16);
}

function lookup3Hash(input) {
  let a = 0x9e3779b9,
    b = 0x9e3779b9,
    c = 0;
  let i = 0;

  while (i < input.length) {
    a += input.charCodeAt(i++) || 0;
    a += (input.charCodeAt(i++) || 0) << 8;
    a += (input.charCodeAt(i++) || 0) << 16;
    a += (input.charCodeAt(i++) || 0) << 24;

    b += input.charCodeAt(i++) || 0;
    b += (input.charCodeAt(i++) || 0) << 8;
    b += (input.charCodeAt(i++) || 0) << 16;
    b += (input.charCodeAt(i++) || 0) << 24;

    c += input.charCodeAt(i++) || 0;
    c += (input.charCodeAt(i++) || 0) << 8;
    c += (input.charCodeAt(i++) || 0) << 16;
    c += (input.charCodeAt(i++) || 0) << 24;

    a = (a - b - c) & 0xffffffff;
    a ^= c >>> 13;
    b = (b - c - a) & 0xffffffff;
    b ^= a << 8;
    c = (c - a - b) & 0xffffffff;
    c ^= b >>> 13;
    a = (a - b - c) & 0xffffffff;
    a ^= c >>> 12;
    b = (b - c - a) & 0xffffffff;
    b ^= a << 16;
    c = (c - a - b) & 0xffffffff;
    c ^= b >>> 5;
    a = (a - b - c) & 0xffffffff;
    a ^= c >>> 3;
    b = (b - c - a) & 0xffffffff;
    b ^= a << 10;
    c = (c - a - b) & 0xffffffff;
    c ^= b >>> 15;
  }

  return (c >>> 0).toString(16);
}

function superFastHash(input) {
  let hash = input.length;
  for (let i = 0; i < input.length; i++) {
    hash += input.charCodeAt(i);
    hash ^= hash << 16;
    hash += hash >>> 11;
  }
  hash ^= hash << 3;
  hash += hash >>> 5;
  hash ^= hash << 4;
  hash += hash >>> 17;
  hash ^= hash << 25;
  hash += hash >>> 6;
  return (hash >>> 0).toString(16);
}

function maPrime2cHash(input) {
  let hash = 0;
  for (let i = 0; i < input.length; i++) {
    hash = (hash * 1000003) ^ input.charCodeAt(i);
  }
  return (hash >>> 0).toString(16);
}

function spookyHash(input) {
  let hash = 0;
  for (let i = 0; i < input.length; i++) {
    hash = hash * 31 + input.charCodeAt(i);
    hash = ((hash << 13) | (hash >>> 19)) & 0xffffffff;
  }
  return (hash >>> 0).toString(16);
}

function paulHsiehHash(input) {
  let hash = input.length;
  for (let i = 0; i < input.length; i++) {
    hash += input.charCodeAt(i);
    hash ^= hash << 10;
    hash += hash >>> 1;
  }
  hash ^= hash << 3;
  hash += hash >>> 5;
  hash ^= hash << 4;
  hash += hash >>> 17;
  hash ^= hash << 25;
  hash += hash >>> 6;
  return (hash >>> 0).toString(16);
}

function bobJenkinsHash(input) {
  let hash = 0;
  for (let i = 0; i < input.length; i++) {
    hash += input.charCodeAt(i);
    hash += hash << 10;
    hash ^= hash >>> 6;
  }
  hash += hash << 3;
  hash ^= hash >>> 11;
  hash += hash << 15;
  return (hash >>> 0).toString(16);
}

function thomasWangHash(input) {
  let hash = 0;
  for (let i = 0; i < input.length; i++) {
    hash += input.charCodeAt(i);
  }
  hash = hash ^ 61 ^ (hash >>> 16);
  hash = hash + (hash << 3);
  hash = hash ^ (hash >>> 4);
  hash = hash * 0x27d4eb2d;
  hash = hash ^ (hash >>> 15);
  return (hash >>> 0).toString(16);
}

function knuthHash(input) {
  let hash = input.length;
  for (let i = 0; i < input.length; i++) {
    hash = (hash << 5) ^ (hash >>> 27) ^ input.charCodeAt(i);
  }
  return (hash >>> 0).toString(16);
}
