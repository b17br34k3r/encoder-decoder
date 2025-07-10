// Encoding functions
function encodeText() {
  const input = document.getElementById("encode-input").value;
  const resultsContainer = document.getElementById("encode-results");

  if (!input.trim()) {
    resultsContainer.innerHTML =
      '<div class="error">Please enter text to encode</div>';
    return;
  }

  showLoading("encode-results");

  // Simulate processing time for UX
  setTimeout(() => {
    clearResults("encode-results");

    try {
      // Base encodings
      resultsContainer.appendChild(createResultItem("Base64", btoa(input)));
      resultsContainer.appendChild(
        createResultItem("Base32", base32Encode(input))
      );
      resultsContainer.appendChild(
        createResultItem("Base16", stringToHex(input))
      );

      // Hex and Binary
      resultsContainer.appendChild(createResultItem("Hex", stringToHex(input)));
      resultsContainer.appendChild(
        createResultItem("Binary", stringToBinary(input))
      );
      resultsContainer.appendChild(
        createResultItem("Octal", stringToOctal(input))
      );

      // URL and HTML
      resultsContainer.appendChild(
        createResultItem("URL", encodeURIComponent(input))
      );
      resultsContainer.appendChild(createResultItem("HTML", htmlEncode(input)));
      resultsContainer.appendChild(createResultItem("XML", xmlEncode(input)));

      // Cipher encodings
      resultsContainer.appendChild(createResultItem("ROT13", rot13(input)));
      resultsContainer.appendChild(createResultItem("ROT47", rot47(input)));
      resultsContainer.appendChild(
        createResultItem("Caesar (3)", caesarCipher(input, 3))
      );
      resultsContainer.appendChild(
        createResultItem("Atbash", atbashCipher(input))
      );

      // Morse and Bacon
      resultsContainer.appendChild(
        createResultItem("Morse", morseEncode(input))
      );
      resultsContainer.appendChild(
        createResultItem("Bacon", baconEncode(input))
      );

      // Other encodings
      resultsContainer.appendChild(
        createResultItem("Reverse", input.split("").reverse().join(""))
      );
      resultsContainer.appendChild(
        createResultItem("ASCII", stringToAscii(input))
      );
      resultsContainer.appendChild(
        createResultItem("Phonetic", phoneticEncode(input))
      );
    } catch (error) {
      resultsContainer.innerHTML = `<div class="error">Encoding error: ${error.message}</div>`;
    }
  }, 500);
}

// Base32 encoding
function base32Encode(str) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  let result = "";

  for (let i = 0; i < str.length; i++) {
    bits += str.charCodeAt(i).toString(2).padStart(8, "0");
  }

  for (let i = 0; i < bits.length; i += 5) {
    const chunk = bits.substr(i, 5).padEnd(5, "0");
    result += alphabet[parseInt(chunk, 2)];
  }

  // Add padding
  while (result.length % 8 !== 0) {
    result += "=";
  }

  return result;
}

// String to hex
function stringToHex(str) {
  return Array.from(str)
    .map((char) => char.charCodeAt(0).toString(16).padStart(2, "0"))
    .join("");
}

// String to binary
function stringToBinary(str) {
  return Array.from(str)
    .map((char) => char.charCodeAt(0).toString(2).padStart(8, "0"))
    .join(" ");
}

// String to octal
function stringToOctal(str) {
  return Array.from(str)
    .map((char) => char.charCodeAt(0).toString(8))
    .join(" ");
}

// HTML encoding
function htmlEncode(str) {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

// XML encoding
function xmlEncode(str) {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

// ROT13
function rot13(str) {
  return str.replace(/[A-Za-z]/g, function (char) {
    const start = char <= "Z" ? 65 : 97;
    return String.fromCharCode(
      ((char.charCodeAt(0) - start + 13) % 26) + start
    );
  });
}

// ROT47
function rot47(str) {
  return str.replace(/[!-~]/g, function (char) {
    return String.fromCharCode(33 + ((char.charCodeAt(0) - 33 + 47) % 94));
  });
}

// Caesar cipher
function caesarCipher(str, shift) {
  return str.replace(/[A-Za-z]/g, function (char) {
    const start = char <= "Z" ? 65 : 97;
    return String.fromCharCode(
      ((char.charCodeAt(0) - start + shift) % 26) + start
    );
  });
}

// Atbash cipher
function atbashCipher(str) {
  return str.replace(/[A-Za-z]/g, function (char) {
    if (char <= "Z") {
      return String.fromCharCode(90 - (char.charCodeAt(0) - 65));
    } else {
      return String.fromCharCode(122 - (char.charCodeAt(0) - 97));
    }
  });
}

// Morse code encoding
function morseEncode(str) {
  const morseMap = {
    A: ".-",
    B: "-...",
    C: "-.-.",
    D: "-..",
    E: ".",
    F: "..-.",
    G: "--.",
    H: "....",
    I: "..",
    J: ".---",
    K: "-.-",
    L: ".-..",
    M: "--",
    N: "-.",
    O: "---",
    P: ".--.",
    Q: "--.-",
    R: ".-.",
    S: "...",
    T: "-",
    U: "..-",
    V: "...-",
    W: ".--",
    X: "-..-",
    Y: "-.--",
    Z: "--..",
    0: "-----",
    1: ".----",
    2: "..---",
    3: "...--",
    4: "....-",
    5: ".....",
    6: "-....",
    7: "--...",
    8: "---..",
    9: "----.",
    " ": "/",
  };

  return str
    .toUpperCase()
    .split("")
    .map((char) => morseMap[char] || char)
    .join(" ");
}

// Bacon cipher encoding
function baconEncode(str) {
  const baconMap = {
    A: "AAAAA",
    B: "AAAAB",
    C: "AAABA",
    D: "AAABB",
    E: "AABAA",
    F: "AABAB",
    G: "AABBA",
    H: "AABBB",
    I: "ABAAA",
    J: "ABAAB",
    K: "ABABA",
    L: "ABABB",
    M: "ABBAA",
    N: "ABBAB",
    O: "ABBBA",
    P: "ABBBB",
    Q: "BAAAA",
    R: "BAAAB",
    S: "BAABA",
    T: "BAABB",
    U: "BABAA",
    V: "BABAB",
    W: "BABBA",
    X: "BABBB",
    Y: "BBAAA",
    Z: "BBAAB",
  };

  return str
    .toUpperCase()
    .split("")
    .map((char) => baconMap[char] || "")
    .join("");
}

// String to ASCII codes
function stringToAscii(str) {
  return Array.from(str)
    .map((char) => char.charCodeAt(0))
    .join(" ");
}

// Phonetic alphabet encoding
function phoneticEncode(str) {
  const phoneticMap = {
    A: "Alpha",
    B: "Bravo",
    C: "Charlie",
    D: "Delta",
    E: "Echo",
    F: "Foxtrot",
    G: "Golf",
    H: "Hotel",
    I: "India",
    J: "Juliet",
    K: "Kilo",
    L: "Lima",
    M: "Mike",
    N: "November",
    O: "Oscar",
    P: "Papa",
    Q: "Quebec",
    R: "Romeo",
    S: "Sierra",
    T: "Tango",
    U: "Uniform",
    V: "Victor",
    W: "Whiskey",
    X: "X-ray",
    Y: "Yankee",
    Z: "Zulu",
  };

  return str
    .toUpperCase()
    .split("")
    .map((char) => phoneticMap[char] || char)
    .join(" ");
}
