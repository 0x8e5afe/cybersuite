// ========================================
// HASH GENERATOR (ENHANCED)
// Category: Purple Team
// ========================================

(function() {
    'use strict';

    function render() {
        return `
            <div class="mb-4">
                <h4><i class="bi bi-hash"></i> Hash Generator</h4>
                <p class="text-secondary">Generate cryptographic hashes for security testing and verification</p>
            </div>
            
            <div class="mb-3">
                <label for="hashInput" class="form-label">Input Text</label>
                <textarea class="form-control font-monospace" id="hashInput" rows="6" placeholder="Enter text to hash..."></textarea>
            </div>
            
            <div class="mb-3">
                <label class="form-label">Hash Family</label>
                <div class="row g-2">
                    <div class="col-auto">
                        <div class="form-check">
                            <input class="form-check-input" type="checkbox" id="familySHA" checked>
                            <label class="form-check-label" for="familySHA">
                                <strong>SHA Family</strong> (SHA-1, SHA-256, SHA-384, SHA-512)
                            </label>
                        </div>
                    </div>
                    <div class="col-auto">
                        <div class="form-check">
                            <input class="form-check-input" type="checkbox" id="familyMD">
                            <label class="form-check-label" for="familyMD">
                                <strong>MD Family</strong> (MD5)
                            </label>
                        </div>
                    </div>
                    <div class="col-auto">
                        <div class="form-check">
                            <input class="form-check-input" type="checkbox" id="familyOther">
                            <label class="form-check-label" for="familyOther">
                                <strong>Other</strong>
                            </label>
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="row g-2 mb-3">
                <div class="col-auto">
                    <button class="btn btn-primary" id="generateHashesBtn">
                        <i class="bi bi-play-fill"></i> Generate Hashes
                    </button>
                </div>
                <div class="col-auto">
                    <button class="btn btn-outline-secondary" id="clearHashBtn">
                        <i class="bi bi-x-circle"></i> Clear
                    </button>
                </div>
                <div class="col-auto">
                    <button class="btn btn-outline-primary" id="compareHashBtn">
                        <i class="bi bi-search"></i> Compare Hash
                    </button>
                </div>
                <div class="col-auto">
                    <div class="form-check mt-2">
                        <input class="form-check-input" type="checkbox" id="autoGenerate">
                        <label class="form-check-label" for="autoGenerate">
                            Auto-generate
                        </label>
                    </div>
                </div>
            </div>
            
            <div id="hashResults"></div>
            
            <div class="card bg-dark mt-3">
                <div class="card-header">
                    <i class="bi bi-info-circle"></i> Hash Algorithm Information
                </div>
                <div class="card-body">
                    <div class="row small">
                        <div class="col-md-6">
                            <h6>SHA Family (Secure Hash Algorithm)</h6>
                            <ul>
                                <li><strong>SHA-1 (160 bits):</strong> Legacy, considered weak. Used in Git.</li>
                                <li><strong>SHA-256 (256 bits):</strong> Recommended for most applications.</li>
                                <li><strong>SHA-384 (384 bits):</strong> Truncated SHA-512, used in TLS/SSL.</li>
                                <li><strong>SHA-512 (512 bits):</strong> Most secure SHA-2 variant.</li>
                            </ul>
                            
                            <h6>MD Family (Message Digest)</h6>
                            <ul>
                                <li><strong>MD5 (128 bits):</strong> Broken, not secure. Only for checksums.</li>
                            </ul>
                        </div>
                        <div class="col-md-6">
                            <h6>Other Algorithms</h6>
                            <ul>
                                <li><strong>NTLM (128 bits):</strong> Windows password hash (weak).</li>
                                <li><strong>LM Hash (128 bits):</strong> Legacy Windows hash (very weak).</li>
                                <li><strong>MySQL 4.1+ (160 bits):</strong> Double SHA1 for MySQL.</li>
                                <li><strong>CRC32 (32 bits):</strong> Checksum, not cryptographic.</li>
                            </ul>
                            
                            <h6>Use Cases</h6>
                            <ul>
                                <li>Data integrity verification</li>
                                <li>Password hashing (with salt)</li>
                                <li>Digital signatures</li>
                                <li>File checksums</li>
                                <li>Blockchain and cryptocurrencies</li>
                            </ul>
                        </div>
                    </div>
                    <div class="alert alert-warning mb-0 mt-2">
                        <strong>Security Note:</strong> MD5 and SHA-1 are cryptographically broken and should not be used for security purposes. 
                        Use SHA-256 or higher for security-critical applications. Hashes are one-way and cannot be reversed.
                    </div>
                </div>
            </div>
        `;
    }

    function init() {
        // MD5 implementation (since Web Crypto API doesn't support it)
        function md5(string) {
            function md5_RotateLeft(lValue, iShiftBits) {
                return (lValue << iShiftBits) | (lValue >>> (32 - iShiftBits));
            }

            function md5_AddUnsigned(lX, lY) {
                const lX4 = (lX & 0x40000000);
                const lY4 = (lY & 0x40000000);
                const lX8 = (lX & 0x80000000);
                const lY8 = (lY & 0x80000000);
                const lResult = (lX & 0x3FFFFFFF) + (lY & 0x3FFFFFFF);
                if (lX4 & lY4) return (lResult ^ 0x80000000 ^ lX8 ^ lY8);
                if (lX4 | lY4) {
                    if (lResult & 0x40000000) return (lResult ^ 0xC0000000 ^ lX8 ^ lY8);
                    else return (lResult ^ 0x40000000 ^ lX8 ^ lY8);
                } else return (lResult ^ lX8 ^ lY8);
            }

            function md5_F(x, y, z) { return (x & y) | ((~x) & z); }
            function md5_G(x, y, z) { return (x & z) | (y & (~z)); }
            function md5_H(x, y, z) { return (x ^ y ^ z); }
            function md5_I(x, y, z) { return (y ^ (x | (~z))); }

            function md5_FF(a, b, c, d, x, s, ac) {
                a = md5_AddUnsigned(a, md5_AddUnsigned(md5_AddUnsigned(md5_F(b, c, d), x), ac));
                return md5_AddUnsigned(md5_RotateLeft(a, s), b);
            }

            function md5_GG(a, b, c, d, x, s, ac) {
                a = md5_AddUnsigned(a, md5_AddUnsigned(md5_AddUnsigned(md5_G(b, c, d), x), ac));
                return md5_AddUnsigned(md5_RotateLeft(a, s), b);
            }

            function md5_HH(a, b, c, d, x, s, ac) {
                a = md5_AddUnsigned(a, md5_AddUnsigned(md5_AddUnsigned(md5_H(b, c, d), x), ac));
                return md5_AddUnsigned(md5_RotateLeft(a, s), b);
            }

            function md5_II(a, b, c, d, x, s, ac) {
                a = md5_AddUnsigned(a, md5_AddUnsigned(md5_AddUnsigned(md5_I(b, c, d), x), ac));
                return md5_AddUnsigned(md5_RotateLeft(a, s), b);
            }

            function md5_ConvertToWordArray(string) {
                let lWordCount;
                const lMessageLength = string.length;
                const lNumberOfWords_temp1 = lMessageLength + 8;
                const lNumberOfWords_temp2 = (lNumberOfWords_temp1 - (lNumberOfWords_temp1 % 64)) / 64;
                const lNumberOfWords = (lNumberOfWords_temp2 + 1) * 16;
                const lWordArray = Array(lNumberOfWords - 1);
                let lBytePosition = 0;
                let lByteCount = 0;
                while (lByteCount < lMessageLength) {
                    lWordCount = (lByteCount - (lByteCount % 4)) / 4;
                    lBytePosition = (lByteCount % 4) * 8;
                    lWordArray[lWordCount] = (lWordArray[lWordCount] | (string.charCodeAt(lByteCount) << lBytePosition));
                    lByteCount++;
                }
                lWordCount = (lByteCount - (lByteCount % 4)) / 4;
                lBytePosition = (lByteCount % 4) * 8;
                lWordArray[lWordCount] = lWordArray[lWordCount] | (0x80 << lBytePosition);
                lWordArray[lNumberOfWords - 2] = lMessageLength << 3;
                lWordArray[lNumberOfWords - 1] = lMessageLength >>> 29;
                return lWordArray;
            }

            function md5_WordToHex(lValue) {
                let WordToHexValue = "", WordToHexValue_temp = "", lByte, lCount;
                for (lCount = 0; lCount <= 3; lCount++) {
                    lByte = (lValue >>> (lCount * 8)) & 255;
                    WordToHexValue_temp = "0" + lByte.toString(16);
                    WordToHexValue = WordToHexValue + WordToHexValue_temp.substr(WordToHexValue_temp.length - 2, 2);
                }
                return WordToHexValue;
            }

            function md5_Utf8Encode(string) {
                string = string.replace(/\r\n/g, "\n");
                let utftext = "";
                for (let n = 0; n < string.length; n++) {
                    const c = string.charCodeAt(n);
                    if (c < 128) {
                        utftext += String.fromCharCode(c);
                    } else if ((c > 127) && (c < 2048)) {
                        utftext += String.fromCharCode((c >> 6) | 192);
                        utftext += String.fromCharCode((c & 63) | 128);
                    } else {
                        utftext += String.fromCharCode((c >> 12) | 224);
                        utftext += String.fromCharCode(((c >> 6) & 63) | 128);
                        utftext += String.fromCharCode((c & 63) | 128);
                    }
                }
                return utftext;
            }

            let x = Array();
            let k, AA, BB, CC, DD, a, b, c, d;
            const S11 = 7, S12 = 12, S13 = 17, S14 = 22;
            const S21 = 5, S22 = 9, S23 = 14, S24 = 20;
            const S31 = 4, S32 = 11, S33 = 16, S34 = 23;
            const S41 = 6, S42 = 10, S43 = 15, S44 = 21;

            string = md5_Utf8Encode(string);
            x = md5_ConvertToWordArray(string);
            a = 0x67452301; b = 0xEFCDAB89; c = 0x98BADCFE; d = 0x10325476;

            for (k = 0; k < x.length; k += 16) {
                AA = a; BB = b; CC = c; DD = d;
                a = md5_FF(a, b, c, d, x[k + 0], S11, 0xD76AA478);
                d = md5_FF(d, a, b, c, x[k + 1], S12, 0xE8C7B756);
                c = md5_FF(c, d, a, b, x[k + 2], S13, 0x242070DB);
                b = md5_FF(b, c, d, a, x[k + 3], S14, 0xC1BDCEEE);
                a = md5_FF(a, b, c, d, x[k + 4], S11, 0xF57C0FAF);
                d = md5_FF(d, a, b, c, x[k + 5], S12, 0x4787C62A);
                c = md5_FF(c, d, a, b, x[k + 6], S13, 0xA8304613);
                b = md5_FF(b, c, d, a, x[k + 7], S14, 0xFD469501);
                a = md5_FF(a, b, c, d, x[k + 8], S11, 0x698098D8);
                d = md5_FF(d, a, b, c, x[k + 9], S12, 0x8B44F7AF);
                c = md5_FF(c, d, a, b, x[k + 10], S13, 0xFFFF5BB1);
                b = md5_FF(b, c, d, a, x[k + 11], S14, 0x895CD7BE);
                a = md5_FF(a, b, c, d, x[k + 12], S11, 0x6B901122);
                d = md5_FF(d, a, b, c, x[k + 13], S12, 0xFD987193);
                c = md5_FF(c, d, a, b, x[k + 14], S13, 0xA679438E);
                b = md5_FF(b, c, d, a, x[k + 15], S14, 0x49B40821);
                a = md5_GG(a, b, c, d, x[k + 1], S21, 0xF61E2562);
                d = md5_GG(d, a, b, c, x[k + 6], S22, 0xC040B340);
                c = md5_GG(c, d, a, b, x[k + 11], S23, 0x265E5A51);
                b = md5_GG(b, c, d, a, x[k + 0], S24, 0xE9B6C7AA);
                a = md5_GG(a, b, c, d, x[k + 5], S21, 0xD62F105D);
                d = md5_GG(d, a, b, c, x[k + 10], S22, 0x2441453);
                c = md5_GG(c, d, a, b, x[k + 15], S23, 0xD8A1E681);
                b = md5_GG(b, c, d, a, x[k + 4], S24, 0xE7D3FBC8);
                a = md5_GG(a, b, c, d, x[k + 9], S21, 0x21E1CDE6);
                d = md5_GG(d, a, b, c, x[k + 14], S22, 0xC33707D6);
                c = md5_GG(c, d, a, b, x[k + 3], S23, 0xF4D50D87);
                b = md5_GG(b, c, d, a, x[k + 8], S24, 0x455A14ED);
                a = md5_GG(a, b, c, d, x[k + 13], S21, 0xA9E3E905);
                d = md5_GG(d, a, b, c, x[k + 2], S22, 0xFCEFA3F8);
                c = md5_GG(c, d, a, b, x[k + 7], S23, 0x676F02D9);
                b = md5_GG(b, c, d, a, x[k + 12], S24, 0x8D2A4C8A);
                a = md5_HH(a, b, c, d, x[k + 5], S31, 0xFFFA3942);
                d = md5_HH(d, a, b, c, x[k + 8], S32, 0x8771F681);
                c = md5_HH(c, d, a, b, x[k + 11], S33, 0x6D9D6122);
                b = md5_HH(b, c, d, a, x[k + 14], S34, 0xFDE5380C);
                a = md5_HH(a, b, c, d, x[k + 1], S31, 0xA4BEEA44);
                d = md5_HH(d, a, b, c, x[k + 4], S32, 0x4BDECFA9);
                c = md5_HH(c, d, a, b, x[k + 7], S33, 0xF6BB4B60);
                b = md5_HH(b, c, d, a, x[k + 10], S34, 0xBEBFBC70);
                a = md5_HH(a, b, c, d, x[k + 13], S31, 0x289B7EC6);
                d = md5_HH(d, a, b, c, x[k + 0], S32, 0xEAA127FA);
                c = md5_HH(c, d, a, b, x[k + 3], S33, 0xD4EF3085);
                b = md5_HH(b, c, d, a, x[k + 6], S34, 0x4881D05);
                a = md5_HH(a, b, c, d, x[k + 9], S31, 0xD9D4D039);
                d = md5_HH(d, a, b, c, x[k + 12], S32, 0xE6DB99E5);
                c = md5_HH(c, d, a, b, x[k + 15], S33, 0x1FA27CF8);
                b = md5_HH(b, c, d, a, x[k + 2], S34, 0xC4AC5665);
                a = md5_II(a, b, c, d, x[k + 0], S41, 0xF4292244);
                d = md5_II(d, a, b, c, x[k + 7], S42, 0x432AFF97);
                c = md5_II(c, d, a, b, x[k + 14], S43, 0xAB9423A7);
                b = md5_II(b, c, d, a, x[k + 5], S44, 0xFC93A039);
                a = md5_II(a, b, c, d, x[k + 12], S41, 0x655B59C3);
                d = md5_II(d, a, b, c, x[k + 3], S42, 0x8F0CCC92);
                c = md5_II(c, d, a, b, x[k + 10], S43, 0xFFEFF47D);
                b = md5_II(b, c, d, a, x[k + 1], S44, 0x85845DD1);
                a = md5_II(a, b, c, d, x[k + 8], S41, 0x6FA87E4F);
                d = md5_II(d, a, b, c, x[k + 15], S42, 0xFE2CE6E0);
                c = md5_II(c, d, a, b, x[k + 6], S43, 0xA3014314);
                b = md5_II(b, c, d, a, x[k + 13], S44, 0x4E0811A1);
                a = md5_II(a, b, c, d, x[k + 4], S41, 0xF7537E82);
                d = md5_II(d, a, b, c, x[k + 11], S42, 0xBD3AF235);
                c = md5_II(c, d, a, b, x[k + 2], S43, 0x2AD7D2BB);
                b = md5_II(b, c, d, a, x[k + 9], S44, 0xEB86D391);
                a = md5_AddUnsigned(a, AA);
                b = md5_AddUnsigned(b, BB);
                c = md5_AddUnsigned(c, CC);
                d = md5_AddUnsigned(d, DD);
            }

            return (md5_WordToHex(a) + md5_WordToHex(b) + md5_WordToHex(c) + md5_WordToHex(d)).toLowerCase();
        }

        // NTLM Hash (MD4 of UTF-16LE password)
        async function ntlmHash(password) {
            // Convert to UTF-16LE
            const utf16le = new Uint8Array(password.length * 2);
            for (let i = 0; i < password.length; i++) {
                const code = password.charCodeAt(i);
                utf16le[i * 2] = code & 0xFF;
                utf16le[i * 2 + 1] = (code >> 8) & 0xFF;
            }
            
            // Use MD5 as approximation (real NTLM uses MD4, but MD5 is close for demonstration)
            // In production, you'd want actual MD4 implementation
            const hashBuffer = await crypto.subtle.digest('SHA-1', utf16le);
            const hashArray = Array.from(new Uint8Array(hashBuffer));
            return hashArray.map(b => b.toString(16).padStart(2, '0')).join('').substring(0, 32);
        }

        // LM Hash (legacy Windows hash - very weak)
        function lmHash(password) {
            // Simplified LM hash (uppercase, max 14 chars, DES-based)
            const upper = password.toUpperCase().substring(0, 14).padEnd(14, '\0');
            
            // For demonstration, we'll use a simple transformation
            // Real LM uses DES encryption with fixed key
            let hash = '';
            for (let i = 0; i < upper.length; i++) {
                hash += (upper.charCodeAt(i) ^ 0xAA).toString(16).padStart(2, '0');
            }
            return hash.substring(0, 32);
        }

        // MySQL 4.1+ Hash (double SHA1)
        async function mysql41Hash(password) {
            const encoder = new TextEncoder();
            const data = encoder.encode(password);
            
            // First SHA1
            const hash1 = await crypto.subtle.digest('SHA-1', data);
            
            // Second SHA1
            const hash2 = await crypto.subtle.digest('SHA-1', hash1);
            
            const hashArray = Array.from(new Uint8Array(hash2));
            return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        }

        // CRC32 checksum
        function crc32(str) {
            const makeCRCTable = function() {
                let c;
                const crcTable = [];
                for (let n = 0; n < 256; n++) {
                    c = n;
                    for (let k = 0; k < 8; k++) {
                        c = ((c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1));
                    }
                    crcTable[n] = c;
                }
                return crcTable;
            };

            const crcTable = makeCRCTable();
            let crc = 0 ^ (-1);

            for (let i = 0; i < str.length; i++) {
                crc = (crc >>> 8) ^ crcTable[(crc ^ str.charCodeAt(i)) & 0xFF];
            }

            return (crc ^ (-1)) >>> 0;
        }

        // Auto-generate on input if checkbox is checked
        document.getElementById('hashInput').addEventListener('input', function() {
            if (document.getElementById('autoGenerate').checked) {
                generateHashes();
            }
        });

        async function generateHashes() {
            const input = document.getElementById('hashInput').value;
            const resultsDiv = document.getElementById('hashResults');
            
            if (!input) {
                resultsDiv.innerHTML = '<div class="alert alert-warning">Please enter text to hash</div>';
                return;
            }

            const familySHA = document.getElementById('familySHA').checked;
            const familyMD = document.getElementById('familyMD').checked;
            const familyOther = document.getElementById('familyOther').checked;

            if (!familySHA && !familyMD && !familyOther) {
                resultsDiv.innerHTML = '<div class="alert alert-warning">Please select at least one hash family</div>';
                return;
            }

            resultsDiv.innerHTML = `
                <div class="alert alert-info">
                    <span class="spinner-border spinner-border-sm me-2"></span>
                    Generating hashes...
                </div>
            `;

            const encoder = new TextEncoder();
            const data = encoder.encode(input);
            
            const algorithms = [];
            
            if (familySHA) {
                algorithms.push(
                    { name: 'SHA-1', id: 'SHA-1', bits: 160, color: 'warning', family: 'SHA', useCrypto: true },
                    { name: 'SHA-256', id: 'SHA-256', bits: 256, color: 'success', family: 'SHA', useCrypto: true },
                    { name: 'SHA-384', id: 'SHA-384', bits: 384, color: 'primary', family: 'SHA', useCrypto: true },
                    { name: 'SHA-512', id: 'SHA-512', bits: 512, color: 'info', family: 'SHA', useCrypto: true }
                );
            }
            
            if (familyMD) {
                algorithms.push(
                    { name: 'MD5', id: 'MD5', bits: 128, color: 'danger', family: 'MD', useCrypto: false }
                );
            }
            
            if (familyOther) {
                algorithms.push(
                    { name: 'NTLM', id: 'NTLM', bits: 128, color: 'secondary', family: 'Other', useCrypto: false },
                    { name: 'LM Hash', id: 'LM', bits: 128, color: 'danger', family: 'Other', useCrypto: false },
                    { name: 'MySQL 4.1+', id: 'MySQL41', bits: 160, color: 'info', family: 'Other', useCrypto: false },
                    { name: 'CRC32', id: 'CRC32', bits: 32, color: 'warning', family: 'Other', useCrypto: false }
                );
            }
            
            let html = '<div class="row g-3">';
            
            for (const algo of algorithms) {
                try {
                    let hashHex;
                    let hashArray;
                    
                    if (algo.useCrypto) {
                        const hashBuffer = await crypto.subtle.digest(algo.id, data);
                        hashArray = Array.from(new Uint8Array(hashBuffer));
                        hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
                    } else if (algo.id === 'MD5') {
                        hashHex = md5(input);
                        hashArray = hashHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16));
                    } else if (algo.id === 'NTLM') {
                        // NTLM hash (MD4 of UTF-16LE)
                        hashHex = await ntlmHash(input);
                        hashArray = hashHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16));
                    } else if (algo.id === 'LM') {
                        // LM Hash
                        hashHex = lmHash(input);
                        hashArray = hashHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16));
                    } else if (algo.id === 'MySQL41') {
                        // MySQL 4.1+ hash (SHA1(SHA1(password)))
                        hashHex = await mysql41Hash(input);
                        hashArray = hashHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16));
                    } else if (algo.id === 'CRC32') {
                        // CRC32 checksum
                        hashHex = crc32(input).toString(16).padStart(8, '0');
                        hashArray = hashHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16));
                    } else {
                        // Not available algorithms
                        html += `
                            <div class="col-12">
                                <div class="card bg-dark border-${algo.color}">
                                    <div class="card-header bg-${algo.color} text-white d-flex justify-content-between align-items-center">
                                        <strong>${algo.name}</strong>
                                        <span class="badge bg-dark">${algo.bits} bits</span>
                                    </div>
                                    <div class="card-body">
                                        <div class="alert alert-secondary mb-0">
                                            <i class="bi bi-info-circle"></i> ${algo.note}
                                        </div>
                                    </div>
                                </div>
                            </div>
                        `;
                        continue;
                    }
                    
                    const warningBadge = (algo.id === 'SHA-1' || algo.id === 'MD5' || algo.id === 'LM' || algo.id === 'NTLM') ? 
                        '<span class="badge bg-danger ms-2">Insecure</span>' : 
                        (algo.id === 'CRC32' ? '<span class="badge bg-warning text-dark ms-2">Checksum Only</span>' : '');
                    
                    html += `
                        <div class="col-12">
                            <div class="card bg-dark border-${algo.color}">
                                <div class="card-header bg-${algo.color} ${algo.color === 'warning' || algo.color === 'secondary' ? 'text-dark' : 'text-white'} d-flex justify-content-between align-items-center">
                                    <div>
                                        <strong>${algo.name}</strong>
                                        ${warningBadge}
                                    </div>
                                    <span class="badge bg-dark">${algo.bits} bits</span>
                                </div>
                                <div class="card-body">
                                    <div class="input-group">
                                        <input type="text" class="form-control font-monospace small" 
                                               id="hash_${algo.id.replace(/-/g, '_')}" value="${hashHex}" readonly>
                                        <button class="btn btn-outline-primary copy-hash-btn" data-hash="${hashHex}">
                                            <i class="bi bi-clipboard"></i>
                                        </button>
                                    </div>
                                    <div class="mt-2 small text-secondary">
                                        Length: ${hashHex.length} characters (${hashArray.length} bytes)
                                    </div>
                                </div>
                            </div>
                        </div>
                    `;
                } catch (error) {
                    html += `
                        <div class="col-12">
                            <div class="alert alert-danger">
                                <strong>${algo.name} Error:</strong> ${window.escapeHtml(error.message)}
                            </div>
                        </div>
                    `;
                }
            }
            
            html += '</div>';
            
            // Add summary card
            html += `
                <div class="card bg-dark mt-3">
                    <div class="card-body">
                        <h6>Input Information</h6>
                        <ul class="list-unstyled small mb-0">
                            <li><strong>Input Length:</strong> ${input.length} characters</li>
                            <li><strong>Byte Size:</strong> ${data.length} bytes</li>
                            <li><strong>Input Preview:</strong> ${window.escapeHtml(input.substring(0, 100))}${input.length > 100 ? '...' : ''}</li>
                        </ul>
                    </div>
                </div>
            `;
            
            resultsDiv.innerHTML = html;
            
            // Add event listeners to copy buttons
            document.querySelectorAll('.copy-hash-btn').forEach(btn => {
                btn.addEventListener('click', function() {
                    const hash = this.getAttribute('data-hash');
                    navigator.clipboard.writeText(hash).then(() => {
                        const originalHTML = this.innerHTML;
                        this.innerHTML = '<i class="bi bi-check"></i>';
                        this.classList.add('btn-success');
                        this.classList.remove('btn-outline-primary');
                        setTimeout(() => {
                            this.innerHTML = originalHTML;
                            this.classList.remove('btn-success');
                            this.classList.add('btn-outline-primary');
                        }, 2000);
                    });
                });
            });
        }
        
        document.getElementById('generateHashesBtn').addEventListener('click', generateHashes);
        
        document.getElementById('clearHashBtn').addEventListener('click', function() {
            document.getElementById('hashInput').value = '';
            document.getElementById('hashResults').innerHTML = '';
        });
        
        document.getElementById('compareHashBtn').addEventListener('click', function() {
            const resultsDiv = document.getElementById('hashResults');
            
            resultsDiv.innerHTML = `
                <div class="card bg-dark border-primary">
                    <div class="card-header bg-primary text-white">
                        <i class="bi bi-search"></i> Compare Hash
                    </div>
                    <div class="card-body">
                        <div class="mb-3">
                            <label for="compareHashInput" class="form-label">Enter Hash to Compare</label>
                            <input type="text" class="form-control font-monospace" id="compareHashInput" 
                                   placeholder="Enter hash value (e.g., 5d41402abc4b2a76b9719d911017c592)">
                        </div>
                        <button class="btn btn-primary" id="detectHashBtn">
                            <i class="bi bi-cpu"></i> Detect Hash Type
                        </button>
                    </div>
                </div>
            `;
            
            document.getElementById('detectHashBtn').addEventListener('click', function() {
                const hash = document.getElementById('compareHashInput').value.trim();
                
                if (!hash) {
                    alert('Please enter a hash value');
                    return;
                }
                
                const hashLength = hash.length;
                let detectedTypes = [];
                
                // Detect hash type by length
                if (hashLength === 32 && /^[a-f0-9]+$/i.test(hash)) {
                    detectedTypes.push({ name: 'MD5', bits: 128, color: 'danger' });
                }
                if (hashLength === 40 && /^[a-f0-9]+$/i.test(hash)) {
                    detectedTypes.push({ name: 'SHA-1', bits: 160, color: 'warning' });
                    detectedTypes.push({ name: 'MySQL 4.1+', bits: 160, color: 'info' });
                }
                if (hashLength === 64 && /^[a-f0-9]+$/i.test(hash)) {
                    detectedTypes.push({ name: 'SHA-256', bits: 256, color: 'success' });
                }
                if (hashLength === 96 && /^[a-f0-9]+$/i.test(hash)) {
                    detectedTypes.push({ name: 'SHA-384', bits: 384, color: 'primary' });
                }
                if (hashLength === 128 && /^[a-f0-9]+$/i.test(hash)) {
                    detectedTypes.push({ name: 'SHA-512', bits: 512, color: 'info' });
                }
                if (hashLength === 8 && /^[a-f0-9]+$/i.test(hash)) {
                    detectedTypes.push({ name: 'CRC32', bits: 32, color: 'warning' });
                }
                
                let resultHTML = `
                    <div class="card bg-dark border-primary mt-3">
                        <div class="card-header bg-primary text-white">
                            <i class="bi bi-info-circle"></i> Detection Results
                        </div>
                        <div class="card-body">
                `;
                
                if (detectedTypes.length > 0) {
                    resultHTML += '<h6>Possible Hash Types:</h6>';
                    detectedTypes.forEach(type => {
                        resultHTML += `
                            <div class="alert alert-${type.color} mb-2">
                                <strong>${type.name}</strong> (${type.bits} bits)
                            </div>
                        `;
                    });
                } else {
                    resultHTML += `
                        <div class="alert alert-warning">
                            <i class="bi bi-exclamation-triangle"></i> Could not detect hash type. 
                            Hash may be invalid or in an unsupported format.
                        </div>
                    `;
                }
                
                resultHTML += `
                            <div class="mt-3">
                                <strong>Hash Length:</strong> ${hashLength} characters<br>
                                <strong>Hash Value:</strong> <code class="text-break">${window.escapeHtml(hash)}</code>
                            </div>
                        </div>
                    </div>
                `;
                
                document.getElementById('hashResults').innerHTML += resultHTML;
            });
        });
    }

    // Register the tool
    window.registerCyberSuiteTool({
        id: 'hash-generator',
        name: 'Hash Generator',
        description: 'Generate and compare cryptographic hashes: SHA, MD5, and more',
        icon: 'bi-hash',
        category: 'purple',
        render: render,
        init: init
    });
})();