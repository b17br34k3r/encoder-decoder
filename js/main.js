// Main application logic
let currentTab = "encode";

// Tab switching functionality
function showTab(tabName) {
  // Hide all tabs
  const tabs = document.querySelectorAll(".tab-content");
  tabs.forEach((tab) => tab.classList.remove("active"));

  // Remove active class from all buttons
  const buttons = document.querySelectorAll(".tab-button");
  buttons.forEach((button) => button.classList.remove("active"));

  // Show selected tab
  const tab = document.getElementById(tabName);
  if (!tab) {
    console.error(`Tab with ID ${tabName} not found`);
    showNotification("Tab not found!", "error");
    return;
  }
  tab.classList.add("active");

  // Add active class to clicked button
  if (event && event.target) {
    event.target.classList.add("active");
  }

  currentTab = tabName;

  // Handle decode format visibility for caesar shift
  if (tabName === "decode") {
    handleDecodeFormatChange();
  }
}

// Format selection handler for decode tab
function handleDecodeFormatChange() {
  const formatSelect = document.getElementById("decode-format");
  const caesarShift = document.getElementById("caesar-shift");
  if (formatSelect && caesarShift) {
    if (formatSelect.value === "caesar") {
      caesarShift.classList.remove("hidden");
    } else {
      caesarShift.classList.add("hidden");
    }
  }
}

// Add decode format event listener
document.addEventListener("DOMContentLoaded", () => {
  const formatSelect = document.getElementById("decode-format");
  if (formatSelect) {
    formatSelect.addEventListener("change", handleDecodeFormatChange);
  }
  handleDecodeFormatChange();
});

// Copy to clipboard functionality
function copyToClipboard(text) {
  navigator.clipboard.writeText(text).then(
    function () {
      showNotification("Copied to clipboard!", "success");
    },
    function () {
      // Fallback for older browsers
      const textArea = document.createElement("textarea");
      textArea.value = text;
      document.body.appendChild(textArea);
      textArea.select();
      document.execCommand("copy");
      document.body.removeChild(textArea);
      showNotification("Copied to clipboard!", "success");
    }
  );
}

// Show notification
function showNotification(message, type = "info") {
  const notification = document.createElement("div");
  notification.className = `notification ${type}`;
  notification.textContent = message;
  notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 15px 20px;
        border-radius: 8px;
        color: white;
        font-weight: 500;
        z-index: 1000;
        animation: slideIn 0.3s ease;
    `;

  if (type === "success") {
    notification.style.background = "#48bb78";
  } else if (type === "error") {
    notification.style.background = "#e53e3e";
  } else {
    notification.style.background = "#667eea";
  }

  document.body.appendChild(notification);

  setTimeout(() => {
    notification.style.animation = "slideOut 0.3s ease";
    setTimeout(() => {
      document.body.removeChild(notification);
    }, 300);
  }, 3000);
}

// Add CSS for notifications
const style = document.createElement("style");
style.textContent = `
    @keyframes slideIn {
        from { transform: translateX(100%); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
    }
    
    @keyframes slideOut {
        from { transform: translateX(0); opacity: 1; }
        to { transform: translateX(100%); opacity: 0; }
    }
`;
document.head.appendChild(style);

// Create result item with copy functionality
function createResultItem(label, value, type = "encode") {
  const item = document.createElement("div");
  item.className = "result-item";

  const labelEl = document.createElement("label");
  labelEl.textContent = label;

  const valueEl = document.createElement("div");
  valueEl.className = "result-value";
  valueEl.textContent = value || "N/A";

  const copyBtn = document.createElement("button");
  copyBtn.className = "copy-btn";
  copyBtn.innerHTML = '<i class="fas fa-copy"></i>';
  copyBtn.onclick = (e) => {
    e.stopPropagation();
    copyToClipboard(value);
  };

  valueEl.appendChild(copyBtn);
  valueEl.onclick = () => copyToClipboard(value);

  item.appendChild(labelEl);
  item.appendChild(valueEl);

  return item;
}

// Clear results
function clearResults(containerId) {
  const container = document.getElementById(containerId);
  if (container) {
    container.innerHTML = "";
  }
}

// Show loading state
function showLoading(containerId) {
  const container = document.getElementById(containerId);
  if (container) {
    container.innerHTML = '<div class="loading">Processing...</div>';
  } else {
    console.error(`Container with ID ${containerId} not found`);
  }
}

// Initialize the application
document.addEventListener("DOMContentLoaded", function () {
  // Set up keyboard shortcuts
  document.addEventListener("keydown", function (e) {
    if (e.ctrlKey || e.metaKey) {
      switch (e.key) {
        case "1":
          e.preventDefault();
          showTab("encode");
          break;
        case "2":
          e.preventDefault();
          showTab("decode");
          break;
        case "3":
          e.preventDefault();
          showTab("hash");
          break;
        case "4":
          e.preventDefault();
          showTab("hash-analysis");
          break;
        case "5":
          e.preventDefault();
          showTab("analyze");
          break;
      }
    }
  });

  // Auto-resize textareas
  const textareas = document.querySelectorAll("textarea");
  textareas.forEach((textarea) => {
    textarea.addEventListener("input", function () {
      this.style.height = "auto";
      this.style.height = Math.min(this.scrollHeight, 300) + "px";
    });
  });

  // Initialize decode format visibility
  handleDecodeFormatChange();

  console.log("🔐 Universal Text Encoder/Decoder initialized");
});
