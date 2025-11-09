# 🛠️ CyberSuite 

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Bootstrap](https://img.shields.io/badge/Bootstrap-5.3-purple.svg)](https://getbootstrap.com)
[![Security Tools](https://img.shields.io/badge/Tools-13-red.svg)](https://github.com)



> ⚠️ Disclaimer: 
> **CyberSuite is for educational and authorized security testing only.**
> - Only use on systems you own or have explicit permission to test
> - Unauthorized access to computer systems is illegal
> - Authors are not responsible for misuse


---

## 🎯 What is CyberSuite?

CyberSuite is a **modular, browser-based security toolkit** built with Bootstrap 5 dark mode, designed for security professionals who need quick access to essential penetration testing and security analysis tools. Everything runs client-side - your data never leaves your machine.

![Cybersuite](assets/screenshot.png) 



---

### ✨ Key Features

- **🚀 Zero Installation**: Pure HTML/CSS/JS - runs in any modern browser
- **🎨 Bootstrap Dark Theme**: Professional UI with responsive design
- **⚡ Lightning Fast**: No backend, no dependencies, pure client-side
- **🔒 Privacy First**: All processing happens locally
- **🧩 Modular Architecture**: Easy to extend with new tools
- **📱 Mobile Friendly**: Works on desktop, tablet, and mobile

---

## 🛠️ Tools Included (13 Tools)

### ⚔️ Red Team Tools (Offensive Security)

1. **🎯 Clickjacking PoC Generator**
   - Generate ready-to-use clickjacking proof of concepts
   - Adjustable iframe opacity for testing
   
2. **📝 CSRF PoC Generator**
   - Create Cross-Site Request Forgery proof of concepts
   - Support for GET, POST methods
   
3. **🐚 Reverse Shell Generator**
   - Generate reverse shell payloads
   - Multiple languages: Bash, Python, PHP, PowerShell, etc.
   
4. **📋 Attack Lists Generator**
   - Generate custom wordlists for fuzzing
   - Numeric, alphabetic, date-based, and custom lists

### 💜 Purple Team Tools (Offensive + Defensive)

5. **🔐 JWT Tool**
   - Decode and analyze JWT tokens
   - Generate custom JWTs with various algorithms
   - Basic Security vulnerability detection
   
6. **🔄 Encoder/Decoder**
   - Support for Base64, URL, Hex, HTML entities, Unicode
   - Quick encode/decode for payload crafting
   
7. **#️⃣ Hash Generator**
   - Generate SHA-1, SHA-256, SHA-384, SHA-512 hashes
   
8. **🔒 Encryption Tool**
   - Encrypt/decrypt text using AES-256-GCM
   - PBKDF2 key derivation
   
9. **🔑 HTTP Security Headers Checker**
   - Analyze security headers (CSP, HSTS, X-Frame-Options, etc.)
   - Detect misconfigurations and headers containing sensitive information
   
10. **🌐 CORS Misconfiguration Checker**
    - Test for CORS vulnerabilities
    - Detect origin reflection and wildcard configs
    
11. **🛡️ Password Generator**
    - Generate cryptographically secure passwords
    - Customizable length and character sets
    
12. **⚡ Password Cracking Complexity**
    - Calculate time to crack passwords
    - Keyspace and attack speed analysis
    
13. **⚠️ CVSS v3.1 Calculator**
    - Calculate CVSS scores for vulnerabilities
    - Generate vector strings

---

## 🚀 Quick Start

### Option 1: Direct Usage (Simplest)

```bash
# Clone the repository
git clone https://github.com/0x8e5afe/cybersuite.git
cd cybersuite

# Open in browser
open index.html
```

### Option 2: Local Web Server (Recommended)

```bash
# Using Python 3
python3 -m http.server 8000

# Then open: http://localhost:8000
```

### Option 3: Deploy to Web

Deploy to GitHub Pages, Netlify, or any static hosting service. Just upload all files!

---

## 📁 Project Structure

```
secuccino/
├── index.html              # Main HTML entry point
├── styles.css              # Custom Bootstrap enhancements
├── app.js                  # Core application & tool loader
├── README.md               # This file
└── tools/                  # Modular tools directory
    ├── tool_1.js
    ├── tool_2.js
    ├── tool_3.js
    ├── etc...
```

---

## 🔧 Developing New Tools

### Tool Development Guide

Creating a new tool for CyberSuite is straightforward. Each tool is a self-contained JavaScript file that registers itself with the core application.

### Tool Anatomy

Every tool consists of three main parts:

1. **render()**: Returns HTML string for the tool's UI
2. **init()**: Initializes event handlers and functionality
3. **Registration**: Registers the tool with CyberSuite

### Complete Tool Skeleton

```javascript
// ========================================
// YOUR TOOL NAME
// Category: red, blue, or purple
// ========================================

(function() {
    'use strict';

    /**
     * Render function - Returns HTML for the tool's interface
     * Uses Bootstrap 5 classes for styling
     */
    function render() {
        return `
            <!-- Tool Header -->
            <div class="mb-4">
                <h4><i class="bi bi-YOUR-ICON"></i> Tool Name</h4>
                <p class="text-secondary">Tool description</p>
            </div>
            
            <!-- Tool Form/Interface -->
            <div class="mb-3">
                <label for="inputId" class="form-label">Input Label</label>
                <input type="text" class="form-control" id="inputId" placeholder="Enter text">
            </div>
            
            <button class="btn btn-primary" onclick="yourFunction()">
                <i class="bi bi-play-fill"></i> Execute
            </button>
            
            <!-- Results Container -->
            <div id="yourResults" class="mt-3"></div>
        `;
    }

    /**
     * Init function - Set up event handlers and tool logic
     * All functions must be attached to window object to be accessible
     */
    function init() {
        // Your tool logic here
        window.yourFunction = function() {
            const input = document.getElementById('inputId').value;
            const resultsDiv = document.getElementById('yourResults');
            
            // Validate input
            if (!input) {
                resultsDiv.innerHTML = '<div class="alert alert-warning">Please enter input</div>';
                return;
            }
            
            try {
                // Your processing logic
                const result = processInput(input);
                
                // Display results using Bootstrap components
                resultsDiv.innerHTML = `
                    <div class="alert alert-success">
                        <h6 class="alert-heading">Success!</h6>
                        <p class="mb-0">${window.escapeHtml(result)}</p>
                    </div>
                `;
            } catch (error) {
                // Error handling
                resultsDiv.innerHTML = `
                    <div class="alert alert-danger">
                        <strong>Error:</strong> ${window.escapeHtml(error.message)}
                    </div>
                `;
            }
        };
        
        // Helper function
        function processInput(input) {
            // Your logic here
            return input.toUpperCase();
        }
    }

    /**
     * Register the tool with CyberSuite
     */
    window.registerCyberSuiteTool({
        id: 'unique-tool-id',              // Unique identifier (lowercase, hyphens)
        name: 'Your Tool Name',            // Display name
        description: 'What your tool does', // Short description
        icon: 'bi-YOUR-ICON',              // Bootstrap icon class
        category: 'purple',                 // 'red', 'blue', or 'purple'
        render: render,                     // Render function
        init: init                          // Init function
    });
})();
```

### Bootstrap Components Reference

CyberSuite uses Bootstrap 5 dark mode. Here are common components:

#### Alerts

```html
<!-- Success -->
<div class="alert alert-success">Success message</div>

<!-- Info -->
<div class="alert alert-info">Info message</div>

<!-- Warning -->
<div class="alert alert-warning">Warning message</div>

<!-- Danger -->
<div class="alert alert-danger">Error message</div>
```

#### Form Controls

```html
<!-- Text Input -->
<div class="mb-3">
    <label for="myInput" class="form-label">Label</label>
    <input type="text" class="form-control" id="myInput">
</div>

<!-- Textarea -->
<textarea class="form-control" rows="5"></textarea>

<!-- Select -->
<select class="form-select">
    <option>Option 1</option>
</select>

<!-- Checkbox -->
<div class="form-check">
    <input class="form-check-input" type="checkbox" id="check1">
    <label class="form-check-label" for="check1">Label</label>
</div>
```

#### Buttons

```html
<button class="btn btn-primary">Primary</button>
<button class="btn btn-success">Success</button>
<button class="btn btn-danger">Danger</button>
<button class="btn btn-outline-primary">Outline</button>
```

#### Cards

```html
<div class="card bg-dark">
    <div class="card-header bg-primary text-dark">
        Header
    </div>
    <div class="card-body">
        Content
    </div>
</div>
```

#### Tabs

```html
<ul class="nav nav-tabs mb-3">
    <li class="nav-item">
        <button class="nav-link active" data-bs-toggle="tab" data-bs-target="#tab1">
            Tab 1
        </button>
    </li>
</ul>

<div class="tab-content">
    <div class="tab-pane fade show active" id="tab1">
        Content 1
    </div>
</div>
```

### Available Utility Functions

The core application provides these utility functions:

```javascript
// Display results with Bootstrap alerts
window.displayResults(containerId, [
    { type: 'success', title: 'Title', desc: 'Description' },
    { type: 'warning', title: 'Warning', desc: 'Details' }
]);

// Copy to clipboard with visual feedback
window.copyToClipboard(text, buttonElement);

// Download file
window.downloadFile('filename.txt', content, 'text/plain');

// Escape HTML (prevent XSS)
window.escapeHtml(userInput);
```

### Icon Reference

Use Bootstrap Icons (https://icons.getbootstrap.com/):

- `bi-key-fill` - Security/Auth
- `bi-shield-fill` - Protection
- `bi-lock-fill` - Encryption
- `bi-unlock-fill` - Decryption
- `bi-code-slash` - Code/Development
- `bi-bug-fill` - Vulnerabilities
- `bi-exclamation-triangle-fill` - Warnings
- `bi-check-circle-fill` - Success
- Many more available!

### Adding Your Tool

1. **Create your tool file**: `tools/your-tool.js`
2. **Add to app.js**: Edit `loadAllTools()` function, add your file to the array:
   ```javascript
   const toolFiles = [
       // ... existing tools
       'tools/your-tool.js'
   ];
   ```
3. **Test**: Refresh browser and your tool appears automatically!

### Best Practices

1. **Always validate input**: Check for empty, invalid, or malicious input
2. **Handle errors gracefully**: Use try-catch blocks
3. **Escape HTML output**: Always use `window.escapeHtml()` for user input
4. **Use semantic HTML**: Proper labels, ARIA attributes for accessibility
5. **Be responsive**: Test on different screen sizes
6. **Document your code**: Add comments explaining complex logic
7. **Test edge cases**: Empty input, very long input, special characters

### Example: Simple Base64 Encoder

Here's a complete minimal example:

```javascript
(function() {
    'use strict';

    function render() {
        return `
            <div class="mb-4">
                <h4><i class="bi bi-file-code"></i> Base64 Encoder</h4>
                <p class="text-secondary">Encode text to Base64</p>
            </div>
            
            <div class="mb-3">
                <label for="b64Input" class="form-label">Input Text</label>
                <textarea class="form-control" id="b64Input" rows="4"></textarea>
            </div>
            
            <button class="btn btn-primary" onclick="encodeB64()">
                <i class="bi bi-arrow-right"></i> Encode
            </button>
            
            <div id="b64Results" class="mt-3"></div>
        `;
    }

    function init() {
        window.encodeB64 = function() {
            const input = document.getElementById('b64Input').value;
            const results = document.getElementById('b64Results');
            
            if (!input) {
                results.innerHTML = '<div class="alert alert-warning">Enter text</div>';
                return;
            }
            
            try {
                const encoded = btoa(unescape(encodeURIComponent(input)));
                results.innerHTML = `
                    <div class="alert alert-success">
                        <div class="code-block">${window.escapeHtml(encoded)}</div>
                        <button class="btn btn-sm btn-outline-primary mt-2" 
                                onclick="copyToClipboard('${encoded.replace(/'/g, "\\'")}', this)">
                            <i class="bi bi-clipboard"></i> Copy
                        </button>
                    </div>
                `;
            } catch (e) {
                results.innerHTML = `<div class="alert alert-danger">Error: ${e.message}</div>`;
            }
        };
    }

    window.registerCyberSuiteTool({
        id: 'base64-encoder',
        name: 'Base64 Encoder',
        description: 'Encode text to Base64 format',
        icon: 'bi-file-code',
        category: 'purple',
        render: render,
        init: init
    });
})();
```

---

## 🤝 Contributing

Contributions welcome! Whether it's:

- 🐛 Bug fixes
- ✨ New tools
- 📝 Documentation improvements
- 🎨 UI/UX enhancements

### How to Contribute

1. Fork the repository
2. Create feature branch: `git checkout -b feature/amazing-tool`
3. Follow the tool development guide above
4. Test thoroughly
5. Commit: `git commit -m 'Add amazing tool'`
6. Push: `git push origin feature/amazing-tool`
7. Open a Pull Request

---



## 📜 License

MIT License - feel free to use, modify, and distribute!

---



## 📞 Support

- 🐛 **Issues**: [GitHub Issues](https://github.com/0x8e5afe/cybersuite/issues)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/0x8e5afe/cybersuite/discussions)
- ⭐ **Star** the repo if you find it useful!

---

<div align="center">

<br>


Made with ❤️ by [0x8e5afe](https://github.com/0x8e5afe/)

[⭐ Star on GitHub](https://github.com/0x8e5afe/cybersuite)

</div>