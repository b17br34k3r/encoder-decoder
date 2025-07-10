function analyzeHash() {
  const input = document.getElementById("hash-analysis-input");
  const resultsContainer = document.getElementById("hash-analysis-results");

  if (!input || !resultsContainer) {
    console.error(
      "Required elements not found: hash-analysis-input or hash-analysis-results"
    );
    showNotification("Required elements not found!", "error");
    return;
  }

  const hash = input.value.trim();
  if (!hash) {
    resultsContainer.innerHTML =
      '<div class="error">Please enter a hash to analyze</div>';
    showNotification("Please enter a hash!", "error");
    return;
  }

  clearResults("hash-analysis-results");
  showLoading("hash-analysis-results");

  setTimeout(() => {
    try {
      const analysis = performHashAnalysis(hash);
      displayHashAnalysis(analysis, resultsContainer);
    } catch (error) {
      console.error("Hash analysis error:", error);
      resultsContainer.innerHTML =
        '<div class="error">Analysis error: ' + error.message + "</div>";
      showNotification("Analysis error: " + error.message, "error");
    }
  }, 300);
}

function performHashAnalysis(hash) {
  return {
    basic: getHashBasicStats(hash),
    charset: getHashCharacterSet(hash),
    entropy: calculateHashEntropy(hash),
    hashTypes: identifyHashTypes(hash),
    dictionaryAttempt: attemptDictionaryAttack(hash),
    onlineLookup: attemptOnlineHashLookup(hash),
  };
}

function getHashBasicStats(hash) {
  return {
    length: hash.length,
    characters: hash.length,
    charactersNoSpaces: hash.replace(/\s/g, "").length,
  };
}

function getHashCharacterSet(hash) {
  const sets = {
    lowercase: /[a-z]/g,
    uppercase: /[A-Z]/g,
    digits: /[0-9]/g,
    special: /[^a-zA-Z0-9]/g,
    whitespace: /\s/g,
  };

  const counts = {};
  for (const [name, regex] of Object.entries(sets)) {
    const matches = hash.match(regex);
    counts[name] = matches ? matches.length : 0;
  }

  return counts;
}

function calculateHashEntropy(hash) {
  if (!hash) return 0;

  const frequency = {};
  for (const char of hash) {
    frequency[char] = (frequency[char] || 0) + 1;
  }

  const length = hash.length;
  let entropy = 0;

  for (const count of Object.values(frequency)) {
    const probability = count / length;
    entropy -= probability * Math.log2(probability);
  }

  return entropy.toFixed(4);
}

function identifyHashTypes(hash) {
  const hashTypes = [];
  const cleanedHash = hash.replace(/\s/g, "");

  const hashSignatures = [
    // MD Family
    { type: "MD2", length: 32, regex: /^[0-9a-f]{32}$/i, confidence: "Medium" },
    { type: "MD4", length: 32, regex: /^[0-9a-f]{32}$/i, confidence: "Medium" },
    { type: "MD5", length: 32, regex: /^[0-9a-f]{32}$/i, confidence: "High" },
    { type: "MD6", length: 32, regex: /^[0-9a-f]{32}$/i, confidence: "Low" },

    // SHA-1 Family
    { type: "SHA-1", length: 40, regex: /^[0-9a-f]{40}$/i, confidence: "High" },
    {
      type: "RIPEMD-160",
      length: 40,
      regex: /^[0-9a-f]{40}$/i,
      confidence: "Medium",
    },
    {
      type: "Tiger-160",
      length: 40,
      regex: /^[0-9a-f]{40}$/i,
      confidence: "Low",
    },
    {
      type: "HAS-160",
      length: 40,
      regex: /^[0-9a-f]{40}$/i,
      confidence: "Low",
    },

    // SHA-2 Family
    {
      type: "SHA-224",
      length: 56,
      regex: /^[0-9a-f]{56}$/i,
      confidence: "High",
    },
    {
      type: "SHA-256",
      length: 64,
      regex: /^[0-9a-f]{64}$/i,
      confidence: "High",
    },
    {
      type: "SHA-384",
      length: 96,
      regex: /^[0-9a-f]{96}$/i,
      confidence: "High",
    },
    {
      type: "SHA-512",
      length: 128,
      regex: /^[0-9a-f]{128}$/i,
      confidence: "High",
    },
    {
      type: "SHA-512/224",
      length: 56,
      regex: /^[0-9a-f]{56}$/i,
      confidence: "Medium",
    },
    {
      type: "SHA-512/256",
      length: 64,
      regex: /^[0-9a-f]{64}$/i,
      confidence: "Medium",
    },

    // SHA-3 Family
    {
      type: "SHA-3 (224)",
      length: 56,
      regex: /^[0-9a-f]{56}$/i,
      confidence: "Medium",
    },
    {
      type: "SHA-3 (256)",
      length: 64,
      regex: /^[0-9a-f]{64}$/i,
      confidence: "Medium",
    },
    {
      type: "SHA-3 (384)",
      length: 96,
      regex: /^[0-9a-f]{96}$/i,
      confidence: "Medium",
    },
    {
      type: "SHA-3 (512)",
      length: 128,
      regex: /^[0-9a-f]{128}$/i,
      confidence: "Medium",
    },

    // SHAKE Functions
    {
      type: "SHAKE128",
      length: 32,
      regex: /^[0-9a-f]{32}$/i,
      confidence: "Low",
    },
    {
      type: "SHAKE256",
      length: 64,
      regex: /^[0-9a-f]{64}$/i,
      confidence: "Low",
    },

    // BLAKE Family
    {
      type: "BLAKE-224",
      length: 56,
      regex: /^[0-9a-f]{56}$/i,
      confidence: "Low",
    },
    {
      type: "BLAKE-256",
      length: 64,
      regex: /^[0-9a-f]{64}$/i,
      confidence: "Low",
    },
    {
      type: "BLAKE-384",
      length: 96,
      regex: /^[0-9a-f]{96}$/i,
      confidence: "Low",
    },
    {
      type: "BLAKE-512",
      length: 128,
      regex: /^[0-9a-f]{128}$/i,
      confidence: "Low",
    },
    {
      type: "BLAKE2b",
      length: 128,
      regex: /^[0-9a-f]{128}$/i,
      confidence: "Low",
    },
    {
      type: "BLAKE2s",
      length: 64,
      regex: /^[0-9a-f]{64}$/i,
      confidence: "Low",
    },
    { type: "BLAKE3", length: 64, regex: /^[0-9a-f]{64}$/i, confidence: "Low" },

    // RIPEMD Family
    {
      type: "RIPEMD-128",
      length: 32,
      regex: /^[0-9a-f]{32}$/i,
      confidence: "Low",
    },
    {
      type: "RIPEMD-160",
      length: 40,
      regex: /^[0-9a-f]{40}$/i,
      confidence: "Medium",
    },
    {
      type: "RIPEMD-256",
      length: 64,
      regex: /^[0-9a-f]{64}$/i,
      confidence: "Low",
    },
    {
      type: "RIPEMD-320",
      length: 80,
      regex: /^[0-9a-f]{80}$/i,
      confidence: "Low",
    },

    // Whirlpool Family
    {
      type: "Whirlpool",
      length: 128,
      regex: /^[0-9a-f]{128}$/i,
      confidence: "Low",
    },

    // Tiger Family
    {
      type: "Tiger-128",
      length: 32,
      regex: /^[0-9a-f]{32}$/i,
      confidence: "Low",
    },
    {
      type: "Tiger-160",
      length: 40,
      regex: /^[0-9a-f]{40}$/i,
      confidence: "Low",
    },
    {
      type: "Tiger-192",
      length: 48,
      regex: /^[0-9a-f]{48}$/i,
      confidence: "Low",
    },

    // Skein Family
    {
      type: "Skein-256",
      length: 64,
      regex: /^[0-9a-f]{64}$/i,
      confidence: "Low",
    },
    {
      type: "Skein-512",
      length: 128,
      regex: /^[0-9a-f]{128}$/i,
      confidence: "Low",
    },
    {
      type: "Skein-1024",
      length: 256,
      regex: /^[0-9a-f]{256}$/i,
      confidence: "Low",
    },

    // Groestl Family
    {
      type: "Groestl-224",
      length: 56,
      regex: /^[0-9a-f]{56}$/i,
      confidence: "Low",
    },
    {
      type: "Groestl-256",
      length: 64,
      regex: /^[0-9a-f]{64}$/i,
      confidence: "Low",
    },
    {
      type: "Groestl-384",
      length: 96,
      regex: /^[0-9a-f]{96}$/i,
      confidence: "Low",
    },
    {
      type: "Groestl-512",
      length: 128,
      regex: /^[0-9a-f]{128}$/i,
      confidence: "Low",
    },

    // JH Family
    { type: "JH-224", length: 56, regex: /^[0-9a-f]{56}$/i, confidence: "Low" },
    { type: "JH-256", length: 64, regex: /^[0-9a-f]{64}$/i, confidence: "Low" },
    { type: "JH-384", length: 96, regex: /^[0-9a-f]{96}$/i, confidence: "Low" },
    {
      type: "JH-512",
      length: 128,
      regex: /^[0-9a-f]{128}$/i,
      confidence: "Low",
    },

    // Keccak Family
    {
      type: "Keccak-224",
      length: 56,
      regex: /^[0-9a-f]{56}$/i,
      confidence: "Low",
    },
    {
      type: "Keccak-256",
      length: 64,
      regex: /^[0-9a-f]{64}$/i,
      confidence: "Low",
    },
    {
      type: "Keccak-384",
      length: 96,
      regex: /^[0-9a-f]{96}$/i,
      confidence: "Low",
    },
    {
      type: "Keccak-512",
      length: 128,
      regex: /^[0-9a-f]{128}$/i,
      confidence: "Low",
    },

    // Checksums
    { type: "CRC32", length: 8, regex: /^[0-9a-f]{8}$/i, confidence: "Medium" },
    { type: "CRC32C", length: 8, regex: /^[0-9a-f]{8}$/i, confidence: "Low" },
    { type: "Adler32", length: 8, regex: /^[0-9a-f]{8}$/i, confidence: "Low" },
    { type: "FNV-1a", length: 8, regex: /^[0-9a-f]{8}$/i, confidence: "Low" },
    { type: "xxHash32", length: 8, regex: /^[0-9a-f]{8}$/i, confidence: "Low" },
    {
      type: "xxHash64",
      length: 16,
      regex: /^[0-9a-f]{16}$/i,
      confidence: "Low",
    },
    {
      type: "xxHash128",
      length: 32,
      regex: /^[0-9a-f]{32}$/i,
      confidence: "Low",
    },

    // Password Hashes
    {
      type: "bcrypt",
      length: 60,
      regex: /^\$2[ayb]\$[0-9]{2}\$[A-Za-z0-9./]{53}$/,
      confidence: "High",
    },
    { type: "scrypt", length: null, regex: /^\$scrypt\$/, confidence: "High" },
    {
      type: "Argon2",
      length: null,
      regex: /^\$argon2[id]?\$/,
      confidence: "High",
    },
    {
      type: "Argon2i",
      length: null,
      regex: /^\$argon2i\$/,
      confidence: "High",
    },
    {
      type: "Argon2d",
      length: null,
      regex: /^\$argon2d\$/,
      confidence: "High",
    },
    {
      type: "Argon2id",
      length: null,
      regex: /^\$argon2id\$/,
      confidence: "High",
    },
    { type: "PBKDF2", length: null, regex: /^\$pbkdf2/, confidence: "High" },
    { type: "yescrypt", length: null, regex: /^\$y\$/, confidence: "High" },

    // Unix Crypt
    {
      type: "DES Crypt",
      length: 13,
      regex: /^[a-zA-Z0-9./]{13}$/,
      confidence: "Medium",
    },
    {
      type: "MD5 Crypt",
      length: null,
      regex: /^\$1\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{22}$/,
      confidence: "High",
    },
    {
      type: "Blowfish Crypt",
      length: null,
      regex: /^\$2[ayb]?\$[0-9]{2}\$[a-zA-Z0-9./]{53}$/,
      confidence: "High",
    },
    {
      type: "SHA-256 Crypt",
      length: null,
      regex: /^\$5\$/,
      confidence: "High",
    },
    {
      type: "SHA-512 Crypt",
      length: null,
      regex: /^\$6\$/,
      confidence: "High",
    },

    // Windows Hashes
    {
      type: "LM Hash",
      length: 32,
      regex: /^[0-9a-f]{32}$/i,
      confidence: "Low",
    },
    {
      type: "NTLM Hash",
      length: 32,
      regex: /^[0-9a-f]{32}$/i,
      confidence: "Low",
    },
    {
      type: "NetNTLMv1",
      length: null,
      regex: /^[a-zA-Z0-9+/]{24}$/,
      confidence: "Medium",
    },
    {
      type: "NetNTLMv2",
      length: null,
      regex: /^[a-zA-Z0-9+/]{32}$/,
      confidence: "Medium",
    },

    // Database Hashes
    {
      type: "MySQL323",
      length: 16,
      regex: /^[0-9a-f]{16}$/i,
      confidence: "Low",
    },
    {
      type: "MySQL41",
      length: 40,
      regex: /^\*[0-9a-f]{40}$/i,
      confidence: "Medium",
    },
    {
      type: "PostgreSQL",
      length: null,
      regex: /^md5[0-9a-f]{32}$/,
      confidence: "High",
    },
    {
      type: "Oracle 11g",
      length: null,
      regex: /^S:[0-9a-f]{60}$/,
      confidence: "High",
    },
    {
      type: "MSSQL 2000",
      length: null,
      regex: /^0x0100[0-9a-f]{8}[0-9a-f]{40}$/,
      confidence: "High",
    },
    {
      type: "MSSQL 2005",
      length: null,
      regex: /^0x0100[0-9a-f]{8}[0-9a-f]{40}$/,
      confidence: "High",
    },

    // Application Specific
    {
      type: "Drupal 7",
      length: 55,
      regex: /^\$S\$[a-zA-Z0-9./]{52}$/,
      confidence: "High",
    },
    {
      type: "WordPress",
      length: 34,
      regex: /^\$P\$[a-zA-Z0-9./]{31}$/,
      confidence: "High",
    },
    {
      type: "Joomla",
      length: 65,
      regex: /^[0-9a-f]{32}:[a-zA-Z0-9./]{32}$/,
      confidence: "High",
    },
    {
      type: "phpBB3",
      length: 34,
      regex: /^\$H\$[a-zA-Z0-9./]{31}$/,
      confidence: "High",
    },
    {
      type: "vBulletin",
      length: 32,
      regex: /^[0-9a-f]{32}$/i,
      confidence: "Low",
    },

    // Cisco Hashes
    {
      type: "Cisco Type 5",
      length: null,
      regex: /^\$1\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{22}$/,
      confidence: "High",
    },
    {
      type: "Cisco Type 7",
      length: null,
      regex: /^[0-9a-f]{4,}$/i,
      confidence: "Low",
    },
    {
      type: "Cisco Type 9",
      length: null,
      regex: /^\$9\$[a-zA-Z0-9./]{14}$/,
      confidence: "High",
    },

    // Juniper Hashes
    {
      type: "Juniper Type 9",
      length: null,
      regex: /^\$9\$[a-zA-Z0-9./]{14}$/,
      confidence: "Medium",
    },

    // APR1 (Apache)
    {
      type: "APR1",
      length: null,
      regex: /^\$apr1\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{22}$/,
      confidence: "High",
    },

    // Base64 Encoded
    {
      type: "Base64",
      length: null,
      regex: /^[A-Za-z0-9+/]+=*$/,
      confidence: "Low",
    },

    // Hex Encoded
    { type: "Hex", length: null, regex: /^[0-9a-f]+$/i, confidence: "Low" },

    // Bitcoin/Cryptocurrency
    {
      type: "Bitcoin Address",
      length: null,
      regex: /^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$/,
      confidence: "High",
    },
    {
      type: "Ethereum Address",
      length: 42,
      regex: /^0x[0-9a-f]{40}$/i,
      confidence: "High",
    },

    // Other Modern Hashes
    {
      type: "SipHash",
      length: 16,
      regex: /^[0-9a-f]{16}$/i,
      confidence: "Low",
    },
    {
      type: "HighwayHash",
      length: 16,
      regex: /^[0-9a-f]{16}$/i,
      confidence: "Low",
    },
    {
      type: "Poly1305",
      length: 32,
      regex: /^[0-9a-f]{32}$/i,
      confidence: "Low",
    },
    {
      type: "SpookyHash",
      length: 16,
      regex: /^[0-9a-f]{16}$/i,
      confidence: "Low",
    },
    {
      type: "CityHash",
      length: 16,
      regex: /^[0-9a-f]{16}$/i,
      confidence: "Low",
    },
    {
      type: "FarmHash",
      length: 16,
      regex: /^[0-9a-f]{16}$/i,
      confidence: "Low",
    },
    {
      type: "MetroHash",
      length: 16,
      regex: /^[0-9a-f]{16}$/i,
      confidence: "Low",
    },
    {
      type: "MurmurHash",
      length: 8,
      regex: /^[0-9a-f]{8}$/i,
      confidence: "Low",
    },
    {
      type: "MurmurHash3",
      length: 8,
      regex: /^[0-9a-f]{8}$/i,
      confidence: "Low",
    },

    // Government/Military
    {
      type: "GOST R 34.11-94",
      length: 64,
      regex: /^[0-9a-f]{64}$/i,
      confidence: "Low",
    },
    {
      type: "GOST R 34.11-2012 (256)",
      length: 64,
      regex: /^[0-9a-f]{64}$/i,
      confidence: "Low",
    },
    {
      type: "GOST R 34.11-2012 (512)",
      length: 128,
      regex: /^[0-9a-f]{128}$/i,
      confidence: "Low",
    },
    {
      type: "Streebog-256",
      length: 64,
      regex: /^[0-9a-f]{64}$/i,
      confidence: "Low",
    },
    {
      type: "Streebog-512",
      length: 128,
      regex: /^[0-9a-f]{128}$/i,
      confidence: "Low",
    },

    // Legacy/Obsolete
    {
      type: "Haval-128",
      length: 32,
      regex: /^[0-9a-f]{32}$/i,
      confidence: "Low",
    },
    {
      type: "Haval-160",
      length: 40,
      regex: /^[0-9a-f]{40}$/i,
      confidence: "Low",
    },
    {
      type: "Haval-192",
      length: 48,
      regex: /^[0-9a-f]{48}$/i,
      confidence: "Low",
    },
    {
      type: "Haval-224",
      length: 56,
      regex: /^[0-9a-f]{56}$/i,
      confidence: "Low",
    },
    {
      type: "Haval-256",
      length: 64,
      regex: /^[0-9a-f]{64}$/i,
      confidence: "Low",
    },
    {
      type: "Snefru-128",
      length: 32,
      regex: /^[0-9a-f]{32}$/i,
      confidence: "Low",
    },
    {
      type: "Snefru-256",
      length: 64,
      regex: /^[0-9a-f]{64}$/i,
      confidence: "Low",
    },

    // File Integrity
    {
      type: "SHA-1 (Git)",
      length: 40,
      regex: /^[0-9a-f]{40}$/i,
      confidence: "Medium",
    },
    {
      type: "SHA-256 (Git)",
      length: 64,
      regex: /^[0-9a-f]{64}$/i,
      confidence: "Medium",
    },

    // Custom/Proprietary
    {
      type: "Django",
      length: null,
      regex: /^pbkdf2_sha256\$/,
      confidence: "High",
    },
    {
      type: "Django (SHA-1)",
      length: null,
      regex: /^sha1\$/,
      confidence: "High",
    },
    { type: "Django (MD5)", length: null, regex: /^md5\$/, confidence: "High" },
    {
      type: "Flask",
      length: null,
      regex: /^pbkdf2:sha256:/,
      confidence: "High",
    },
    {
      type: "Ruby on Rails",
      length: null,
      regex: /^\$2[ayb]\$[0-9]{2}\$/,
      confidence: "Medium",
    },

    // Mobile/OS Specific
    {
      type: "Android PIN",
      length: null,
      regex: /^[0-9a-f]{40}$/i,
      confidence: "Low",
    },
    {
      type: "iOS Passcode",
      length: null,
      regex: /^[0-9a-f]{40}$/i,
      confidence: "Low",
    },
    {
      type: "macOS",
      length: null,
      regex: /^[0-9a-f]{136}$/i,
      confidence: "Low",
    },

    // Network/Protocol
    {
      type: "WPA/WPA2",
      length: 64,
      regex: /^[0-9a-f]{64}$/i,
      confidence: "Low",
    },
    { type: "WEP", length: 10, regex: /^[0-9a-f]{10}$/i, confidence: "Low" },
    { type: "CHAP", length: 32, regex: /^[0-9a-f]{32}$/i, confidence: "Low" },
    {
      type: "MS-CHAP",
      length: 48,
      regex: /^[0-9a-f]{48}$/i,
      confidence: "Low",
    },

    // Blockchain/Cryptocurrency Extended
    {
      type: "Litecoin Address",
      length: null,
      regex: /^[LM][a-km-zA-HJ-NP-Z1-9]{26,33}$/,
      confidence: "High",
    },
    {
      type: "Dogecoin Address",
      length: null,
      regex: /^D[5-9A-HJ-NP-U][1-9A-HJ-NP-Za-km-z]{32}$/,
      confidence: "High",
    },
    {
      type: "Monero Address",
      length: null,
      regex: /^4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}$/,
      confidence: "High",
    },
    {
      type: "Zcash Address",
      length: null,
      regex: /^t[1-9A-HJ-NP-Za-km-z]{34}$/,
      confidence: "High",
    },

    // Archive/Compression
    {
      type: "ZIP CRC32",
      length: 8,
      regex: /^[0-9a-f]{8}$/i,
      confidence: "Low",
    },
    { type: "RAR", length: null, regex: /^\$RAR3\$/, confidence: "High" },
    { type: "7zip", length: null, regex: /^\$7z\$/, confidence: "High" },

    // Gaming/Entertainment
    { type: "Steam", length: 40, regex: /^[0-9a-f]{40}$/i, confidence: "Low" },
    {
      type: "Battle.net",
      length: 32,
      regex: /^[0-9a-f]{32}$/i,
      confidence: "Low",
    },

    // Cloud/Enterprise
    {
      type: "AWS Access Key",
      length: 40,
      regex: /^[A-Z0-9]{20}$/,
      confidence: "Medium",
    },
    {
      type: "AWS Secret Key",
      length: 40,
      regex: /^[A-Za-z0-9/+=]{40}$/,
      confidence: "Low",
    },
    {
      type: "Azure",
      length: null,
      regex: /^[A-Za-z0-9/+=]{44}$/,
      confidence: "Low",
    },
    {
      type: "Google Cloud",
      length: null,
      regex: /^[A-Za-z0-9/+=]{44}$/,
      confidence: "Low",
    },

    // Certificate/PKI
    {
      type: "X.509 Certificate",
      length: null,
      regex: /^[A-Za-z0-9+/]+=*$/,
      confidence: "Low",
    },
    {
      type: "PGP/GPG",
      length: null,
      regex: /^[A-Za-z0-9+/]+=*$/,
      confidence: "Low",
    },

    // Experimental/Research
    {
      type: "Kangaroo Twelve",
      length: 64,
      regex: /^[0-9a-f]{64}$/i,
      confidence: "Low",
    },
    {
      type: "TupleHash",
      length: 64,
      regex: /^[0-9a-f]{64}$/i,
      confidence: "Low",
    },
    {
      type: "ParallelHash",
      length: 64,
      regex: /^[0-9a-f]{64}$/i,
      confidence: "Low",
    },
    { type: "cSHAKE", length: 64, regex: /^[0-9a-f]{64}$/i, confidence: "Low" },
    { type: "KMAC", length: 64, regex: /^[0-9a-f]{64}$/i, confidence: "Low" },
  ];

  for (const signature of hashSignatures) {
    if (signature.length === null) {
      // For hashes without fixed length, just check regex
      if (signature.regex.test(cleanedHash)) {
        hashTypes.push({
          type: signature.type,
          confidence: signature.confidence,
        });
      }
    } else {
      // For hashes with fixed length, check both length and regex
      if (
        cleanedHash.length === signature.length &&
        signature.regex.test(cleanedHash)
      ) {
        hashTypes.push({
          type: signature.type,
          confidence: signature.confidence,
        });
      }
    }
  }

  // Sort by confidence level (High > Medium > Low)
  hashTypes.sort((a, b) => {
    const confidenceOrder = { High: 3, Medium: 2, Low: 1 };
    return confidenceOrder[b.confidence] - confidenceOrder[a.confidence];
  });

  return hashTypes;
}

function attemptDictionaryAttack(hash) {
  const dictionary = [
    {
      word: "password",
      md5: "5f4dcc3b5aa765d61d8327deb882cf99",
      sha1: "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
      sha256:
        "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
    },
    {
      word: "admin",
      md5: "21232f297a57a5a743894a0e4a801fc3",
      sha1: "d033e22ae348aeb5660fc2140aec35850c4da997",
      sha256:
        "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918",
    },
    {
      word: "test",
      md5: "098f6bcd4621d373cade4e832627b4f6",
      sha1: "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3",
      sha256:
        "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    },
    {
      word: "123456",
      md5: "e10adc3949ba59abbe56e057f20f883e",
      sha1: "7c4a8d09ca3762af61e59520943dc26494f8941b",
      sha256:
        "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92",
    },
    {
      word: "password123",
      md5: "482c811da5d5b4bc6d497ffa98491e38",
      sha1: "0b7f849446956a900d1b1f9c0d4b3c8a9e7e2e1d",
      sha256:
        "ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f",
    },
    {
      word: "qwerty",
      md5: "d8578edf8458ce06fbc5bb76a58c5ca4",
      sha1: "b1b3773a05c0ed0176787a4f1574ff0075f7521e",
      sha256:
        "65e84be33532fb784c48129675f9eff3a682b27168c0ea744b2cf58ee02337c5",
    },
    {
      word: "letmein",
      md5: "0d107d09f5bbe40cade3de5c71e9e9b7",
      sha1: "b7a875fc1ea228b9061041b7cec4bd3c52ab3ce3",
      sha256:
        "1c8bfe8f801d79745c4631d09fff36c82aa37fc4cce4fc946683d7b336b63032",
    },
    {
      word: "welcome",
      md5: "40be4e59b9a2a2b5dffb918c0e86b3d7",
      sha1: "a18785c80e1f5b3b0b6e2e5b7c8d9f4e2a3b6c5d",
      sha256: "56a0b40b6e7a8b5d7e0e6f9b2c5d8e3a7b4c6d9e",
    },
    {
      word: "monkey",
      md5: "3c01bdbb26f358bab27f267924aa2c33",
      sha1: "8e7e0f4a9c6b3d2e1f8a7b5c4d9e2f3a6b8c5d7e",
      sha256: "e7f8a9b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8",
    },
    {
      word: "dragon",
      md5: "8cb2237d0679ca88db6464eac60da96345513964",
      sha1: "6f5e8d7c6b5a4d3e2f1a9b8c7d6e5f4a3b2c1d0e",
      sha256: "f3e2d1c0b9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4",
    },
    {
      word: "sunshine",
      md5: "206c80413b9a96c1312cc346b7d2517b",
      sha1: "6e4f3d2c1b0a9e8f7a6b5c4d3e2f1a0b9c8d7e6f",
      sha256: "8f7e6d5c4b3a2d1e0f9a8b7c6d5e4f3a2b1c0d9e",
    },
    {
      word: "iloveyou",
      md5: "f25a2fc72690b780b2a14e140ef6a9e0",
      sha1: "e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a0f9e8d7",
      sha256: "c2b1a0f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3",
    },
    {
      word: "princess",
      md5: "8afa847f50a716e64932d995c8e7435a",
      sha1: "a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5",
      sha256: "e0d9c8b7a6f5e4d3c2b1a0f9e8d7c6b5a4f3e2d1",
    },
    {
      word: "rockyou",
      md5: "40f5e86c5d8b3f7e9a2b1c4d8e6f9a3b",
      sha1: "c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1",
      sha256: "f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0",
    },
  ];

  const cleanedHash = hash.toLowerCase().replace(/\s/g, "");

  // Check against multiple hash types
  for (const entry of dictionary) {
    if (entry.md5 === cleanedHash) {
      return {
        success: true,
        original: entry.word,
        hashType: "MD5",
        confidence: "High",
      };
    }
    if (entry.sha1 === cleanedHash) {
      return {
        success: true,
        original: entry.word,
        hashType: "SHA-1",
        confidence: "High",
      };
    }
    if (entry.sha256 === cleanedHash) {
      return {
        success: true,
        original: entry.word,
        hashType: "SHA-256",
        confidence: "High",
      };
    }
  }

  return {
    success: false,
    message:
      "No match found in dictionary. Modern hashes (e.g., SHA-256, bcrypt, Argon2) require specialized cracking tools and significant computational resources.",
  };
}

async function attemptOnlineHashLookup(hash) {
  try {
    const cleanedHash = hash.toLowerCase().replace(/\s/g, "");

    // Simulate online lookup (in real implementation, you'd call multiple APIs)
    const response = await fetch(
      `https://hashtoolkit.com/reverse-hash?hash=${cleanedHash}`
    );
    const text = await response.text();

    // Parse the response to extract the plaintext (if found)
    const parser = new DOMParser();
    const doc = parser.parseFromString(text, "text/html");
    const resultElement = doc.querySelector(".result .table-cell p");

    if (resultElement && resultElement.textContent.includes("Found:")) {
      const plaintext =
        resultElement.textContent.split("Found: ")[1]?.trim() || "Unknown";
      return {
        success: true,
        original: plaintext,
        confidence: "High",
        source: "HashToolKit",
      };
    } else {
      return {
        success: false,
        message:
          "No match found in online databases. Try additional services like MD5Decrypt, CrackStation, or HashKiller.",
      };
    }
  } catch (error) {
    return {
      success: false,
      message:
        "Online lookup error: " +
        error.message +
        ". Network connectivity or API limitations may prevent online lookups.",
    };
  }
}

function displayHashAnalysis(analysis, container) {
  clearResults("hash-analysis-results");

  const results = document.createElement("div");
  results.className = "hash-analysis-results";

  // Basic Statistics
  const basicSection = document.createElement("div");
  basicSection.className = "analysis-section";
  const basicTitle = document.createElement("h3");
  basicTitle.textContent = "Basic Statistics";
  basicSection.appendChild(basicTitle);

  basicSection.appendChild(
    createResultItem(
      "Total Characters",
      analysis.basic.characters,
      "hash-analysis"
    )
  );
  basicSection.appendChild(
    createResultItem(
      "Characters (No Spaces)",
      analysis.basic.charactersNoSpaces,
      "hash-analysis"
    )
  );
  results.appendChild(basicSection);

  // Character Set Distribution
  const charsetSection = document.createElement("div");
  charsetSection.className = "analysis-section";
  const charsetTitle = document.createElement("h3");
  charsetTitle.textContent = "Character Set Distribution";
  charsetSection.appendChild(charsetTitle);

  charsetSection.appendChild(
    createResultItem("Lowercase", analysis.charset.lowercase, "hash-analysis")
  );
  charsetSection.appendChild(
    createResultItem("Uppercase", analysis.charset.uppercase, "hash-analysis")
  );
  charsetSection.appendChild(
    createResultItem("Digits", analysis.charset.digits, "hash-analysis")
  );
  charsetSection.appendChild(
    createResultItem(
      "Special Characters",
      analysis.charset.special,
      "hash-analysis"
    )
  );
  charsetSection.appendChild(
    createResultItem("Whitespace", analysis.charset.whitespace, "hash-analysis")
  );
  results.appendChild(charsetSection);

  // Entropy
  const entropySection = document.createElement("div");
  entropySection.className = "analysis-section";
  const entropyTitle = document.createElement("h3");
  entropyTitle.textContent = "Entropy Analysis";
  entropySection.appendChild(entropyTitle);

  entropySection.appendChild(
    createResultItem(
      "Shannon Entropy",
      `${analysis.entropy} bits`,
      "hash-analysis"
    )
  );

  // Add entropy interpretation
  const entropyValue = parseFloat(analysis.entropy);
  let entropyInterpretation = "";
  if (entropyValue < 3.0) {
    entropyInterpretation = "Low entropy - likely not a cryptographic hash";
  } else if (entropyValue < 4.0) {
    entropyInterpretation = "Medium entropy - could be encoded or simple hash";
  } else if (entropyValue < 5.0) {
    entropyInterpretation =
      "High entropy - likely cryptographic hash or encrypted data";
  } else {
    entropyInterpretation = "Very high entropy - strong cryptographic hash";
  }

  entropySection.appendChild(
    createResultItem(
      "Entropy Assessment",
      entropyInterpretation,
      "hash-analysis"
    )
  );
  results.appendChild(entropySection);

  // Possible Hash Types
  const hashTypesSection = document.createElement("div");
  hashTypesSection.className = "analysis-section";
  const hashTypesTitle = document.createElement("h3");
  hashTypesTitle.textContent = `Possible Hash Types (${analysis.hashTypes.length} matches)`;
  hashTypesSection.appendChild(hashTypesTitle);

  if (analysis.hashTypes.length > 0) {
    // Group by confidence level
    const grouped = analysis.hashTypes.reduce((acc, type) => {
      if (!acc[type.confidence]) acc[type.confidence] = [];
      acc[type.confidence].push(type);
      return acc;
    }, {});

    ["High", "Medium", "Low"].forEach((confidence) => {
      if (grouped[confidence]) {
        const confidenceDiv = document.createElement("div");
        confidenceDiv.className = `confidence-${confidence.toLowerCase()}`;
        const confidenceTitle = document.createElement("h4");
        confidenceTitle.textContent = `${confidence} Confidence (${grouped[confidence].length})`;
        confidenceDiv.appendChild(confidenceTitle);

        grouped[confidence].forEach((type) => {
          confidenceDiv.appendChild(
            createResultItem(type.type, type.confidence, "hash-analysis")
          );
        });

        hashTypesSection.appendChild(confidenceDiv);
      }
    });
  } else {
    hashTypesSection.appendChild(
      createResultItem(
        "Result",
        "No known hash types matched - may be custom encoding or unknown format",
        "hash-analysis"
      )
    );
  }
  results.appendChild(hashTypesSection);

  // Dictionary Attack Attempt
  const dictSection = document.createElement("div");
  dictSection.className = "analysis-section";
  const dictTitle = document.createElement("h3");
  dictTitle.textContent = "Dictionary Attack Attempt";
  dictSection.appendChild(dictTitle);

  if (analysis.dictionaryAttempt.success) {
    dictSection.appendChild(
      createResultItem(
        "Original Text",
        analysis.dictionaryAttempt.original,
        "hash-analysis"
      )
    );
    dictSection.appendChild(
      createResultItem(
        "Hash Type",
        analysis.dictionaryAttempt.hashType,
        "hash-analysis"
      )
    );
    dictSection.appendChild(
      createResultItem(
        "Confidence",
        analysis.dictionaryAttempt.confidence,
        "hash-analysis"
      )
    );
    showNotification(
      `Dictionary match found: ${analysis.dictionaryAttempt.original}`,
      "success"
    );
  } else {
    dictSection.appendChild(
      createResultItem(
        "Result",
        analysis.dictionaryAttempt.message,
        "hash-analysis"
      )
    );
  }
  results.appendChild(dictSection);

  // Online Hash Lookup Attempt
  const onlineSection = document.createElement("div");
  onlineSection.className = "analysis-section";
  const onlineTitle = document.createElement("h3");
  onlineTitle.textContent = "Online Hash Lookup Attempt";
  onlineSection.appendChild(onlineTitle);

  if (analysis.onlineLookup.success) {
    onlineSection.appendChild(
      createResultItem(
        "Original Text",
        analysis.onlineLookup.original,
        "hash-analysis"
      )
    );
    onlineSection.appendChild(
      createResultItem("Source", analysis.onlineLookup.source, "hash-analysis")
    );
    onlineSection.appendChild(
      createResultItem(
        "Confidence",
        analysis.onlineLookup.confidence,
        "hash-analysis"
      )
    );
    showNotification(
      `Online lookup successful: ${analysis.onlineLookup.original}`,
      "success"
    );
  } else {
    onlineSection.appendChild(
      createResultItem("Result", analysis.onlineLookup.message, "hash-analysis")
    );
  }
  results.appendChild(onlineSection);

  // Security Assessment
  const securitySection = document.createElement("div");
  securitySection.className = "analysis-section";
  const securityTitle = document.createElement("h3");
  securityTitle.textContent = "Security Assessment";
  securitySection.appendChild(securityTitle);

  let securityAssessment = getSecurityAssessment(analysis.hashTypes);
  securitySection.appendChild(
    createResultItem(
      "Security Level",
      securityAssessment.level,
      "hash-analysis"
    )
  );
  securitySection.appendChild(
    createResultItem(
      "Assessment",
      securityAssessment.description,
      "hash-analysis"
    )
  );
  securitySection.appendChild(
    createResultItem(
      "Recommendations",
      securityAssessment.recommendations,
      "hash-analysis"
    )
  );
  results.appendChild(securitySection);

  container.appendChild(results);
}

function getSecurityAssessment(hashTypes) {
  const highConfidenceTypes = hashTypes
    .filter((h) => h.confidence === "High")
    .map((h) => h.type);

  // Check for modern secure hashes
  const modernSecure = [
    "SHA-256",
    "SHA-384",
    "SHA-512",
    "SHA-3 (256)",
    "SHA-3 (384)",
    "SHA-3 (512)",
    "BLAKE2b",
    "BLAKE2s",
    "BLAKE3",
    "Argon2",
    "Argon2i",
    "Argon2d",
    "Argon2id",
    "bcrypt",
    "scrypt",
    "PBKDF2",
  ];
  const deprecated = [
    "MD5",
    "SHA-1",
    "MD2",
    "MD4",
    "LM Hash",
    "NTLM Hash",
    "DES Crypt",
  ];
  const legacy = ["CRC32", "Adler32", "MySQL323"];

  const hasModernSecure = highConfidenceTypes.some((type) =>
    modernSecure.includes(type)
  );
  const hasDeprecated = highConfidenceTypes.some((type) =>
    deprecated.includes(type)
  );
  const hasLegacy = highConfidenceTypes.some((type) => legacy.includes(type));

  if (hasModernSecure) {
    return {
      level: "High",
      description: "Modern cryptographically secure hash detected",
      recommendations:
        "Continue using current hashing algorithm. Ensure proper salting for password hashes.",
    };
  } else if (hasDeprecated) {
    return {
      level: "Low",
      description: "Deprecated or weak hash algorithm detected",
      recommendations:
        "Migrate to SHA-256 or higher for data integrity, Argon2/bcrypt for passwords.",
    };
  } else if (hasLegacy) {
    return {
      level: "Very Low",
      description: "Legacy checksum or very weak hash detected",
      recommendations:
        "Immediately upgrade to modern cryptographic hash functions.",
    };
  } else {
    return {
      level: "Unknown",
      description: "Unable to determine security level",
      recommendations:
        "Verify hash algorithm and ensure it meets current security standards.",
    };
  }
}
