// Text analysis functions
function analyzeText() {
  const input = document.getElementById("analyze-input").value;
  const resultsContainer = document.getElementById("analyze-results");

  if (!input.trim()) {
    resultsContainer.innerHTML =
      '<div class="error">Please enter text to analyze</div>';
    return;
  }

  showLoading("analyze-results");

  setTimeout(() => {
    try {
      const analysis = performTextAnalysis(input);
      displayAnalysis(analysis, resultsContainer);
    } catch (error) {
      resultsContainer.innerHTML = `<div class="error">Analysis error: ${error.message}</div>`;
    }
  }, 300);
}

function showLoading(containerId) {
  document.getElementById(containerId).innerHTML =
    '<div class="loading">Analyzing...</div>';
}

function performTextAnalysis(text) {
  return {
    basic: getBasicStats(text),
    charset: getCharacterSet(text),
    entropy: calculateEntropy(text),
    patterns: detectPatterns(text),
    frequency: getCharacterFrequency(text),
    encoding: guessEncoding(text),
  };
}

function getBasicStats(text) {
  const lines = text.split("\n");
  const words = text.split(/\s+/).filter((word) => word.length > 0);

  return {
    length: text.length,
    lines: lines.length,
    words: words.length,
    characters: text.length,
    charactersNoSpaces: text.replace(/\s/g, "").length,
    avgWordLength:
      words.length > 0 ? (words.join("").length / words.length).toFixed(2) : 0,
    avgWordsPerLine:
      lines.length > 0 ? (words.length / lines.length).toFixed(2) : 0,
  };
}

function getCharacterSet(text) {
  const sets = {
    lowercase: /[a-z]/g,
    uppercase: /[A-Z]/g,
    digits: /[0-9]/g,
    special: /[^a-zA-Z0-9\s]/g,
    whitespace: /\s/g,
  };

  const counts = {};
  for (const [name, regex] of Object.entries(sets)) {
    const matches = text.match(regex);
    counts[name] = matches ? matches.length : 0;
  }

  return counts;
}

function calculateEntropy(text) {
  if (!text) return 0;

  const frequency = {};
  for (const char of text) {
    frequency[char] = (frequency[char] || 0) + 1;
  }

  const length = text.length;
  let entropy = 0;

  for (const count of Object.values(frequency)) {
    const probability = count / length;
    entropy -= probability * Math.log2(probability);
  }

  return entropy.toFixed(4);
}

function detectPatterns(text) {
  const patterns = [];

  if (/^[A-Za-z0-9+/]*={0,2}$/.test(text)) {
    patterns.push({ type: "Base64-like", confidence: "High" });
  }

  if (/^[A-Z2-7]+=*$/.test(text)) {
    patterns.push({ type: "Base32-like", confidence: "High" });
  }

  if (/^[0-9A-Fa-f]+$/.test(text)) {
    patterns.push({ type: "Hexadecimal", confidence: "High" });
  }

  if (/^[01\s]+$/.test(text)) {
    patterns.push({ type: "Binary", confidence: "High" });
  }

  if (/^[.\-\s/]+$/.test(text)) {
    patterns.push({ type: "Morse Code", confidence: "Medium" });
  }

  if (/%[0-9A-F]{2}/i.test(text)) {
    patterns.push({ type: "URL Encoded", confidence: "Medium" });
  }

  if (/&[a-zA-Z0-9#]+;/.test(text)) {
    patterns.push({ type: "HTML Encoded", confidence: "Medium" });
  }

  if (/^\d+(\s+\d+)*$/.test(text)) {
    const codes = text.split(/\s+/).map(Number);
    if (codes.every((code) => code >= 0 && code <= 127)) {
      patterns.push({ type: "ASCII Codes", confidence: "High" });
    }
  }

  const repeatingPattern = findRepeatingPattern(text);
  if (repeatingPattern) {
    patterns.push({
      type: "Repeating Pattern",
      confidence: "Medium",
      pattern: repeatingPattern,
    });
  }

  return patterns;
}

function findRepeatingPattern(text) {
  for (let len = 1; len <= text.length / 2; len++) {
    const pattern = text.substring(0, len);
    if (text === pattern.repeat(text.length / len)) {
      return pattern;
    }
  }
  return null;
}

function getCharacterFrequency(text) {
  const frequency = {};
  for (const char of text) {
    frequency[char] = (frequency[char] || 0) + 1;
  }

  return Object.entries(frequency)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([char, count]) => ({
      char: char === " " ? "[space]" : char,
      count,
      percentage: ((count / text.length) * 100).toFixed(2),
    }));
}

function guessEncoding(text) {
  const guesses = [];

  const decoders = [
    { name: "Base64", test: isBase64, decode: (t) => atob(t) },
    { name: "Hex", test: isHex, decode: hexToString },
    { name: "Binary", test: isBinary, decode: binaryToString },
    { name: "Morse", test: isMorse, decode: morseDecode },
    { name: "URL", test: isUrlEncoded, decode: decodeURIComponent },
    { name: "HTML", test: isHtmlEncoded, decode: htmlDecode },
  ];

  for (const decoder of decoders) {
    if (decoder.test(text)) {
      try {
        const decoded = decoder.decode(text);
        const readability = calculateReadability(decoded);
        guesses.push({
          type: decoder.name,
          confidence: readability > 0.5 ? "High" : "Medium",
          readability: readability.toFixed(2),
        });
      } catch (e) {
        // Ignore decode errors
      }
    }
  }

  return guesses;
}

function calculateReadability(text) {
  const commonLetters = "etaoinshrdlcumwfgypbvkjxqz";
  const letterCount = {};
  let totalLetters = 0;

  for (const char of text.toLowerCase()) {
    if (char.match(/[a-z]/)) {
      letterCount[char] = (letterCount[char] || 0) + 1;
      totalLetters++;
    }
  }

  if (totalLetters === 0) return 0;

  let score = 0;
  for (let i = 0; i < commonLetters.length; i++) {
    const char = commonLetters[i];
    const frequency = (letterCount[char] || 0) / totalLetters;
    const expectedFrequency = Math.exp(-i * 0.1);
    score += Math.min(frequency, expectedFrequency);
  }

  return score;
}

function isBase64(str) {
  return /^[A-Za-z0-9+/]*={0,2}$/.test(str) && str.length % 4 === 0;
}

function isHex(str) {
  return /^[0-9A-Fa-f]+$/.test(str) && str.length % 2 === 0;
}

function isBinary(str) {
  return /^[01\s]+$/.test(str);
}

function isMorse(str) {
  return /^[.\-\s/]+$/.test(str);
}

function isUrlEncoded(str) {
  return /%[0-9A-F]{2}/i.test(str);
}

function isHtmlEncoded(str) {
  return /&[a-zA-Z0-9#]+;/.test(str);
}

function hexToString(hex) {
  let str = "";
  for (let i = 0; i < hex.length; i += 2) {
    str += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
  }
  return str;
}

function binaryToString(binary) {
  return binary
    .split(" ")
    .map((bin) => String.fromCharCode(parseInt(bin, 2)))
    .join("");
}

function morseDecode(morse) {
  const morseCode = {
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
    ".----": "0",
    "..---": "1",
    "...--": "2",
    "....-": "3",
    ".....": "4",
    "-....": "5",
    "--...": "6",
    "---..": "7",
    "----.": "8",
    "-----": "9",
  };
  return morse
    .split("/")
    .map((code) => morseCode[code.trim()] || "")
    .join("");
}

function htmlDecode(str) {
  const textarea = document.createElement("textarea");
  textarea.innerHTML = str;
  return textarea.value;
}

function displayAnalysis(analysis, container) {
  let html = `
        <div class="analysis-results">
            <h2>Text Analysis Results</h2>
            
            <h3>Basic Statistics</h3>
            <table>
                <tr><td>Total Characters</td><td>${
                  analysis.basic.characters
                }</td></tr>
                <tr><td>Characters (no spaces)</td><td>${
                  analysis.basic.charactersNoSpaces
                }</td></tr>
                <tr><td>Words</td><td>${analysis.basic.words}</td></tr>
                <tr><td>Lines</td><td>${analysis.basic.lines}</td></tr>
                <tr><td>Average Word Length</td><td>${
                  analysis.basic.avgWordLength
                }</td></tr>
                <tr><td>Average Words per Line</td><td>${
                  analysis.basic.avgWordsPerLine
                }</td></tr>
            </table>

            <h3>Character Set Distribution</h3>
            <table>
                <tr><td>Lowercase</td><td>${
                  analysis.charset.lowercase
                }</td></tr>
                <tr><td>Uppercase</td><td>${
                  analysis.charset.uppercase
                }</td></tr>
                <tr><td>Digits</td><td>${analysis.charset.digits}</td></tr>
                <tr><td>Special Characters</td><td>${
                  analysis.charset.special
                }</td></tr>
                <tr><td>Whitespace</td><td>${
                  analysis.charset.whitespace
                }</td></tr>
            </table>

            <h3>Entropy</h3>
            <p>${analysis.entropy} bits</p>

            <h3>Character Frequency (Top 10)</h3>
            <table>
                <tr><th>Character</th><th>Count</th><th>Percentage</th></tr>
                ${analysis.frequency
                  .map(
                    (item) => `
                    <tr>
                        <td>${item.char}</td>
                        <td>${item.count}</td>
                        <td>${item.percentage}%</td>
                    </tr>
                `
                  )
                  .join("")}
            </table>

            <h3>Detected Patterns</h3>
            ${
              analysis.patterns.length > 0
                ? `
                <table>
                    <tr><th>Type</th><th>Confidence</th><th>Details</th></tr>
                    ${analysis.patterns
                      .map(
                        (pattern) => `
                        <tr>
                            <td>${pattern.type}</td>
                            <td>${pattern.confidence}</td>
                            <td>${pattern.pattern || "-"}</td>
                        </tr>
                    `
                      )
                      .join("")}
                </table>
            `
                : "<p>No specific patterns detected</p>"
            }

            <h3>Encoding Guesses</h3>
            ${
              analysis.encoding.length > 0
                ? `
                <table>
                    <tr><th>Type</th><th>Confidence</th><th>Readability</th></tr>
                    ${analysis.encoding
                      .map(
                        (guess) => `
                        <tr>
                            <td>${guess.type}</td>
                            <td>${guess.confidence}</td>
                            <td>${guess.readability}</td>
                        </tr>
                    `
                      )
                      .join("")}
                </table>
            `
                : "<p>No specific encoding detected</p>"
            }
        </div>
    `;

  container.innerHTML = html;
}
