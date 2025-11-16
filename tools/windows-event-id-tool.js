// ========================================
// WINDOWS SECURITY EVENT ID REFERENCE
// Category: Blue Team
// ========================================

(function() {
    'use strict';

    const windowsEvents = {
        1102: {
            name: 'Audit Log Cleared',
            description: 'The security audit log was cleared',
            useCase: 'Detect anti-forensics and evidence destruction attempts',
            logName: 'Security',
            keyFields: ['SubjectUserName', 'SubjectDomainName'],
            detectionTips: 'Critical alert - investigate immediately. Often indicates attacker covering tracks',
            severity: 'danger',
            category: 'Security',
            mitre: ['T1070.001']
        },
        4624: {
            name: 'Successful Logon',
            description: 'An account was successfully logged on',
            useCase: 'Track user authentication, baseline normal activity, detect anomalous logins',
            logName: 'Security',
            keyFields: ['TargetUserName', 'LogonType', 'IpAddress', 'WorkstationName'],
            detectionTips: 'Focus on LogonType 3 (network), 10 (RDP). Monitor for logins from unusual IPs',
            severity: 'info',
            category: 'Authentication',
            mitre: ['T1078']
        },
        4625: {
            name: 'Failed Logon',
            description: 'An account failed to log on',
            useCase: 'Detect brute force attacks, password spraying, credential stuffing',
            logName: 'Security',
            keyFields: ['TargetUserName', 'FailureReason', 'IpAddress', 'WorkstationName'],
            detectionTips: 'Multiple failures from same source = brute force. Multiple accounts = password spray',
            severity: 'warning',
            category: 'Authentication',
            mitre: ['T1110']
        },
        4648: {
            name: 'Logon Using Explicit Credentials',
            description: 'A logon was attempted using explicit credentials',
            useCase: 'Detect credential abuse, lateral movement via RunAs',
            logName: 'Security',
            keyFields: ['SubjectUserName', 'TargetUserName', 'TargetServerName'],
            detectionTips: 'Monitor for privilege escalation attempts and lateral movement patterns',
            severity: 'warning',
            category: 'Authentication',
            mitre: ['T1078', 'T1021']
        },
        4672: {
            name: 'Special Privileges Assigned',
            description: 'Special privileges assigned to new logon',
            useCase: 'Track administrative logons and privilege use',
            logName: 'Security',
            keyFields: ['SubjectUserName', 'PrivilegeList'],
            detectionTips: 'Monitor for SeDebugPrivilege - used in credential dumping attacks',
            severity: 'warning',
            category: 'Privilege Use',
            mitre: ['T1078.002']
        },
        4688: {
            name: 'Process Created',
            description: 'A new process has been created',
            useCase: 'Track process execution, detect malicious commands',
            logName: 'Security',
            keyFields: ['NewProcessName', 'CommandLine', 'ParentProcessName', 'TokenElevationType'],
            detectionTips: 'Enable command line logging. Monitor for PowerShell, cmd, wmic, psexec',
            severity: 'info',
            category: 'Process',
            mitre: ['T1059']
        },
        4689: {
            name: 'Process Terminated',
            description: 'A process has exited',
            useCase: 'Track process lifecycle, detect defense evasion',
            logName: 'Security',
            keyFields: ['ProcessName', 'ProcessId'],
            detectionTips: 'Correlate with 4688 to understand process behavior',
            severity: 'info',
            category: 'Process',
            mitre: []
        },
        4697: {
            name: 'Service Installed',
            description: 'A service was installed on the system',
            useCase: 'Detect persistence mechanisms and malware installation',
            logName: 'Security',
            keyFields: ['ServiceName', 'ServiceFileName', 'SubjectUserName'],
            detectionTips: 'Monitor for services with unusual names or paths, especially in temp directories',
            severity: 'danger',
            category: 'Service',
            mitre: ['T1543.003']
        },
        4698: {
            name: 'Scheduled Task Created',
            description: 'A scheduled task was created',
            useCase: 'Detect persistence and lateral movement via scheduled tasks',
            logName: 'Security',
            keyFields: ['TaskName', 'SubjectUserName', 'TaskContent'],
            detectionTips: 'Review task content for suspicious commands, especially PowerShell or encoded commands',
            severity: 'warning',
            category: 'Scheduled Task',
            mitre: ['T1053.005']
        },
        4699: {
            name: 'Scheduled Task Deleted',
            description: 'A scheduled task was deleted',
            useCase: 'Detect cleanup attempts by attackers',
            logName: 'Security',
            keyFields: ['TaskName', 'SubjectUserName'],
            detectionTips: 'May indicate attacker removing persistence or covering tracks',
            severity: 'warning',
            category: 'Scheduled Task',
            mitre: ['T1070']
        },
        4700: {
            name: 'Scheduled Task Enabled',
            description: 'A scheduled task was enabled',
            useCase: 'Track task modifications for persistence detection',
            logName: 'Security',
            keyFields: ['TaskName', 'SubjectUserName'],
            detectionTips: 'Monitor for re-enabling of suspicious or previously disabled tasks',
            severity: 'info',
            category: 'Scheduled Task',
            mitre: ['T1053.005']
        },
        4701: {
            name: 'Scheduled Task Disabled',
            description: 'A scheduled task was disabled',
            useCase: 'Detect defense evasion attempts',
            logName: 'Security',
            keyFields: ['TaskName', 'SubjectUserName'],
            detectionTips: 'Alert if security-related tasks are disabled',
            severity: 'warning',
            category: 'Scheduled Task',
            mitre: ['T1562.001']
        },
        4702: {
            name: 'Scheduled Task Updated',
            description: 'A scheduled task was updated',
            useCase: 'Detect modifications to legitimate tasks for persistence',
            logName: 'Security',
            keyFields: ['TaskName', 'SubjectUserName', 'TaskContent'],
            detectionTips: 'Review changes to system tasks - common persistence technique',
            severity: 'warning',
            category: 'Scheduled Task',
            mitre: ['T1053.005']
        },
        4719: {
            name: 'System Audit Policy Changed',
            description: 'System audit policy was changed',
            useCase: 'Detect attempts to disable logging and evade detection',
            logName: 'Security',
            keyFields: ['SubjectUserName', 'CategoryId', 'AuditPolicyChanges'],
            detectionTips: 'Critical - attackers may disable logging to hide activity',
            severity: 'danger',
            category: 'Policy Change',
            mitre: ['T1562.002']
        },
        4720: {
            name: 'User Account Created',
            description: 'A user account was created',
            useCase: 'Detect unauthorized account creation for persistence',
            logName: 'Security',
            keyFields: ['TargetUserName', 'SubjectUserName', 'TargetDomainName'],
            detectionTips: 'Monitor for accounts created outside normal processes',
            severity: 'warning',
            category: 'Account Management',
            mitre: ['T1136.001']
        },
        4722: {
            name: 'User Account Enabled',
            description: 'A user account was enabled',
            useCase: 'Detect reactivation of dormant or disabled accounts',
            logName: 'Security',
            keyFields: ['TargetUserName', 'SubjectUserName'],
            detectionTips: 'Alert on enabling of previously disabled accounts, especially admin accounts',
            severity: 'warning',
            category: 'Account Management',
            mitre: ['T1078']
        },
        4724: {
            name: 'Password Reset Attempted',
            description: 'An attempt was made to reset an account password',
            useCase: 'Detect unauthorized password changes',
            logName: 'Security',
            keyFields: ['TargetUserName', 'SubjectUserName'],
            detectionTips: 'Monitor for password resets on privileged accounts',
            severity: 'warning',
            category: 'Account Management',
            mitre: ['T1098']
        },
        4725: {
            name: 'User Account Disabled',
            description: 'A user account was disabled',
            useCase: 'Track account lifecycle and detect unauthorized changes',
            logName: 'Security',
            keyFields: ['TargetUserName', 'SubjectUserName'],
            detectionTips: 'May indicate incident response or account compromise',
            severity: 'info',
            category: 'Account Management',
            mitre: []
        },
        4726: {
            name: 'User Account Deleted',
            description: 'A user account was deleted',
            useCase: 'Track account deletion and detect cleanup attempts',
            logName: 'Security',
            keyFields: ['TargetUserName', 'SubjectUserName'],
            detectionTips: 'Attackers may delete accounts to cover tracks',
            severity: 'warning',
            category: 'Account Management',
            mitre: ['T1070']
        },
        4732: {
            name: 'Member Added to Security-Enabled Local Group',
            description: 'A member was added to a security-enabled local group',
            useCase: 'Detect privilege escalation via group membership',
            logName: 'Security',
            keyFields: ['TargetUserName', 'SubjectUserName', 'TargetSid'],
            detectionTips: 'Alert on additions to Administrators, Remote Desktop Users, Backup Operators',
            severity: 'danger',
            category: 'Account Management',
            mitre: ['T1078.003']
        },
        4733: {
            name: 'Member Removed from Security-Enabled Local Group',
            description: 'A member was removed from a security-enabled local group',
            useCase: 'Track group membership changes',
            logName: 'Security',
            keyFields: ['TargetUserName', 'SubjectUserName', 'TargetSid'],
            detectionTips: 'May indicate cleanup or legitimate access revocation',
            severity: 'info',
            category: 'Account Management',
            mitre: []
        },
        4738: {
            name: 'User Account Changed',
            description: 'A user account was changed',
            useCase: 'Detect unauthorized account modifications',
            logName: 'Security',
            keyFields: ['TargetUserName', 'SubjectUserName', 'PasswordLastSet'],
            detectionTips: 'Monitor for changes to privileged accounts',
            severity: 'warning',
            category: 'Account Management',
            mitre: ['T1098']
        },
        4756: {
            name: 'Member Added to Security-Enabled Universal Group',
            description: 'A member was added to a security-enabled universal group',
            useCase: 'Track domain group membership changes',
            logName: 'Security',
            keyFields: ['MemberName', 'SubjectUserName', 'TargetUserName'],
            detectionTips: 'Monitor Domain Admins, Enterprise Admins additions',
            severity: 'danger',
            category: 'Account Management',
            mitre: ['T1078.002']
        },
        4768: {
            name: 'Kerberos TGT Requested',
            description: 'A Kerberos authentication ticket (TGT) was requested',
            useCase: 'Detect Kerberos attacks, Golden Ticket usage',
            logName: 'Security',
            keyFields: ['TargetUserName', 'IpAddress', 'ServiceName'],
            detectionTips: 'Monitor for unusual encryption types, suspicious IPs, or off-hours requests',
            severity: 'info',
            category: 'Authentication',
            mitre: ['T1558.001']
        },
        4769: {
            name: 'Kerberos Service Ticket Requested',
            description: 'A Kerberos service ticket was requested',
            useCase: 'Detect Kerberoasting, Silver Ticket attacks',
            logName: 'Security',
            keyFields: ['TargetUserName', 'ServiceName', 'TicketEncryptionType'],
            detectionTips: 'Alert on RC4 encryption (0x17) for service tickets - indicates Kerberoasting',
            severity: 'warning',
            category: 'Authentication',
            mitre: ['T1558.003']
        },
        4771: {
            name: 'Kerberos Pre-authentication Failed',
            description: 'Kerberos pre-authentication failed',
            useCase: 'Detect password spray attacks against Kerberos',
            logName: 'Security',
            keyFields: ['TargetUserName', 'IpAddress'],
            detectionTips: 'Multiple failures = password attack. Monitor for AS-REP roasting attempts',
            severity: 'warning',
            category: 'Authentication',
            mitre: ['T1558.004']
        },
        4776: {
            name: 'NTLM Authentication',
            description: 'The computer attempted to validate credentials',
            useCase: 'Track NTLM usage, detect pass-the-hash attacks',
            logName: 'Security',
            keyFields: ['TargetUserName', 'Workstation'],
            detectionTips: 'NTLM should be rare in modern networks. Investigate all usage',
            severity: 'warning',
            category: 'Authentication',
            mitre: ['T1550.002']
        },
        5140: {
            name: 'Network Share Accessed',
            description: 'A network share object was accessed',
            useCase: 'Detect lateral movement via SMB, data exfiltration',
            logName: 'Security',
            keyFields: ['SubjectUserName', 'ShareName', 'IpAddress'],
            detectionTips: 'Monitor for access to ADMIN$, C$, IPC$ from unusual sources',
            severity: 'info',
            category: 'File Share',
            mitre: ['T1021.002']
        },
        5142: {
            name: 'Network Share Added',
            description: 'A network share object was added',
            useCase: 'Detect unauthorized share creation for data staging',
            logName: 'Security',
            keyFields: ['ShareName', 'SubjectUserName'],
            detectionTips: 'Alert on new shares, especially with suspicious names',
            severity: 'warning',
            category: 'File Share',
            mitre: ['T1021.002']
        },
        5145: {
            name: 'Network Share Checked for Access',
            description: 'A network share object was checked to see if client can be granted desired access',
            useCase: 'Detect reconnaissance of file shares',
            logName: 'Security',
            keyFields: ['SubjectUserName', 'ShareName', 'RelativeTargetName', 'IpAddress'],
            detectionTips: 'Multiple rapid checks may indicate automated scanning',
            severity: 'info',
            category: 'File Share',
            mitre: ['T1135']
        },
        7045: {
            name: 'Service Installed (System)',
            description: 'A service was installed in the system',
            useCase: 'Detect malware and persistence via services',
            logName: 'System',
            keyFields: ['ServiceName', 'ImagePath', 'ServiceType', 'AccountName'],
            detectionTips: 'Critical for lateral movement (PsExec). Check ImagePath for suspicious binaries',
            severity: 'danger',
            category: 'Service',
            mitre: ['T1543.003', 'T1021.002']
        },
        1116: {
            name: 'Windows Defender Malware Detected',
            description: 'Windows Defender detected malware or unwanted software',
            useCase: 'Track malware detections and infection attempts',
            logName: 'Microsoft-Windows-Windows Defender/Operational',
            keyFields: ['ThreatName', 'Path', 'ProcessName'],
            detectionTips: 'Investigate immediately - confirmed malicious activity',
            severity: 'danger',
            category: 'Antivirus',
            mitre: []
        },
        1118: {
            name: 'Windows Defender Action Taken',
            description: 'Windows Defender took action on malware',
            useCase: 'Confirm malware remediation',
            logName: 'Microsoft-Windows-Windows Defender/Operational',
            keyFields: ['ThreatName', 'Action', 'Path'],
            detectionTips: 'Verify successful remediation and investigate infection vector',
            severity: 'warning',
            category: 'Antivirus',
            mitre: []
        },
        5001: {
            name: 'Windows Defender Real-time Protection Disabled',
            description: 'Real-time protection was disabled',
            useCase: 'Detect defense evasion attempts',
            logName: 'Microsoft-Windows-Windows Defender/Operational',
            keyFields: ['User'],
            detectionTips: 'Critical alert - attackers disable AV before deploying malware',
            severity: 'danger',
            category: 'Antivirus',
            mitre: ['T1562.001']
        },
        5140: {
            name: 'Network Share Object Accessed',
            description: 'A network share object was accessed',
            useCase: 'Detect lateral movement and data access',
            logName: 'Security',
            keyFields: ['SubjectUserName', 'ShareName', 'ShareLocalPath', 'IpAddress'],
            detectionTips: 'Focus on administrative shares (C$, ADMIN$) and sensitive data repositories',
            severity: 'info',
            category: 'File Share',
            mitre: ['T1021.002']
        },
        7040: {
            name: 'Service Start Type Changed',
            description: 'The start type of a service was changed',
            useCase: 'Detect service manipulation for persistence or defense evasion',
            logName: 'System',
            keyFields: ['ServiceName', 'StartType'],
            detectionTips: 'Monitor for security services being disabled or changed to manual',
            severity: 'warning',
            category: 'Service',
            mitre: ['T1562.001']
        },
        104: {
            name: 'Log File Cleared',
            description: 'The log file was cleared',
            useCase: 'Detect anti-forensics and log deletion',
            logName: 'System',
            keyFields: ['SubjectUserName', 'SubjectDomainName'],
            detectionTips: 'Critical indicator of attacker activity - investigate immediately',
            severity: 'danger',
            category: 'Security',
            mitre: ['T1070.001']
        }
    };

    const categories = [...new Set(Object.values(windowsEvents).map(e => e.category))].sort();
    const logNames = [...new Set(Object.values(windowsEvents).map(e => e.logName))].sort();

    function render() {
        return `
            <div class="section-header">
                <h3 class="mb-1 d-flex align-items-center gap-2">
                    <i class="bi bi-shield-check"></i>
                    <span>Windows Event ID Reference</span>
                </h3>
                <p class="text-secondary mb-0">
                  Comprehensive reference for Windows Security and System event logs.
                </p>
            </div>
            
            <div class="row g-2 mb-3">
                <div class="col-md-4">
                    <label for="winEventSearch" class="form-label small">Search Event ID or Name</label>
                    <input type="text" class="form-control form-control-sm" id="winEventSearch" placeholder="e.g., 4624, logon, service...">
                </div>
                <div class="col-md-4">
                    <label for="winCategoryFilter" class="form-label small">Category</label>
                    <select class="form-select form-select-sm" id="winCategoryFilter">
                        <option value="all">All Categories</option>
                        ${categories.map(cat => `<option value="${cat}">${cat}</option>`).join('')}
                    </select>
                </div>
                <div class="col-md-4">
                    <label for="winLogFilter" class="form-label small">Log Name</label>
                    <select class="form-select form-select-sm" id="winLogFilter">
                        <option value="all">All Logs</option>
                        ${logNames.map(log => `<option value="${log}">${log}</option>`).join('')}
                    </select>
                </div>
            </div>

            <div class="mb-3">
                <div class="btn-group btn-group-sm flex-wrap" role="group">
    <button class="btn btn-outline-danger win-filter-btn"
            type="button"
            onclick="filterWinBySeverity('danger', this)">
        <i class="bi bi-exclamation-octagon-fill"></i> Critical
    </button>

    <button class="btn btn-outline-warning win-filter-btn"
            type="button"
            onclick="filterWinBySeverity('warning', this)">
        <i class="bi bi-exclamation-triangle-fill"></i> Warning
    </button>

    <button class="btn btn-outline-info win-filter-btn"
            type="button"
            onclick="filterWinBySeverity('info', this)">
        <i class="bi bi-info-circle-fill"></i> Info
    </button>

    <button class="btn btn-outline-purple win-filter-btn"
            type="button"
            onclick="showMitreEvents(this)">
        <i class="bi bi-diagram-3"></i> MITRE ATT&CK
    </button>

    <button class="btn btn-outline-secondary"
            type="button"
            onclick="showAllWinEvents()">
        <i class="bi bi-arrow-counterclockwise"></i> Reset
    </button>
</div>
            </div>
            
            <div id="winEventsContainer"></div>
            
            <div class="card bg-dark mt-3">
                <div class="card-body p-2">
                    <h6 class="small mb-2"><i class="bi bi-book"></i> Quick Reference</h6>
                    <div class="row g-2 small">
                        <div class="col-md-4">
                            <strong>Authentication:</strong> 4624, 4625, 4648, 4768, 4769, 4771, 4776
                        </div>
                        <div class="col-md-4">
                            <strong>Privilege Escalation:</strong> 4672, 4732, 4756
                        </div>
                        <div class="col-md-4">
                            <strong>Persistence:</strong> 4697, 4698, 4720, 7045
                        </div>
                        <div class="col-md-4">
                            <strong>Defense Evasion:</strong> 1102, 104, 4719, 5001
                        </div>
                        <div class="col-md-4">
                            <strong>Lateral Movement:</strong> 5140, 5145, 7045
                        </div>
                        <div class="col-md-4">
                            <strong>Account Management:</strong> 4720, 4722, 4724, 4726, 4738
                        </div>
                    </div>
                </div>
            </div>

             <div class="alert alert-info mt-3">
                    <small>
                        <strong><i class="bi bi-lightbulb"></i> Pro Tip:</strong> 
                        Click the <i class="bi bi-clipboard"></i> icon to copy a PowerShell query for retrieving that specific event type.
                    </small>
                </div>
        `;
    }

    function init() {
        renderAllWinEvents();

        document.getElementById('winEventSearch').addEventListener('input', function() {
            filterWinEvents();
        });

        document.getElementById('winCategoryFilter').addEventListener('change', function() {
            filterWinEvents();
        });

        document.getElementById('winLogFilter').addEventListener('change', function() {
            filterWinEvents();
        });

        window.filterWinBySeverity = function(severity) {
            const filtered = Object.entries(windowsEvents).filter(([_, event]) => event.severity === severity);
            renderWinEvents(filtered);
        };

        window.showMitreEvents = function() {
            const filtered = Object.entries(windowsEvents).filter(([_, event]) => event.mitre.length > 0);
            renderWinEvents(filtered);
        };

        window.showAllWinEvents = function() {
            document.getElementById('winEventSearch').value = '';
            document.getElementById('winCategoryFilter').value = 'all';
            document.getElementById('winLogFilter').value = 'all';
            renderAllWinEvents();
        };

        window.copyWinEventQuery = function(eventId, logName) {
            const query = `Get-WinEvent -FilterHashtable @{LogName='${logName}'; ID=${eventId}} -MaxEvents 100`;
            navigator.clipboard.writeText(query).then(() => {
                showWinToast('PowerShell query copied!');
            });
        };

        function filterWinEvents() {
            const query = document.getElementById('winEventSearch').value.toLowerCase();
            const category = document.getElementById('winCategoryFilter').value;
            const logName = document.getElementById('winLogFilter').value;

            let filtered = Object.entries(windowsEvents);

            if (query) {
                filtered = filtered.filter(([id, event]) =>
                    id.includes(query) ||
                    event.name.toLowerCase().includes(query) ||
                    event.description.toLowerCase().includes(query) ||
                    event.useCase.toLowerCase().includes(query) ||
                    event.detectionTips.toLowerCase().includes(query)
                );
            }

            if (category !== 'all') {
                filtered = filtered.filter(([_, event]) => event.category === category);
            }

            if (logName !== 'all') {
                filtered = filtered.filter(([_, event]) => event.logName === logName);
            }

            renderWinEvents(filtered);
        }

        

        function setWinFilterActive(btn) {
    // remove active from all filter buttons
    document.querySelectorAll('.win-filter-btn')
        .forEach(b => b.classList.remove('active'));

    // set active only on the clicked one (if provided)
    if (btn) {
        btn.classList.add('active');
    }
}

window.filterWinBySeverity = function (severity, btn) {
    const filtered = Object.entries(windowsEvents)
        .filter(([_, event]) => event.severity === severity);

    renderWinEvents(filtered);
    setWinFilterActive(btn);
};

window.showMitreEvents = function (btn) {
    const filtered = Object.entries(windowsEvents)
        .filter(([_, event]) => event.mitre.length > 0);

    renderWinEvents(filtered);
    setWinFilterActive(btn);
};

window.showAllWinEvents = function () {
    document.getElementById('winEventSearch').value = '';
    document.getElementById('winCategoryFilter').value = 'all';
    document.getElementById('winLogFilter').value = 'all';

    renderAllWinEvents();
    setWinFilterActive(null); // clear glow on all
};

window.filterWinBySeverity = function (severity, btn) {
    const filtered = Object.entries(windowsEvents)
        .filter(([_, event]) => event.severity === severity);
    renderWinEvents(filtered);
    setWinFilterActive(btn);
};

window.showMitreEvents = function (btn) {
    const filtered = Object.entries(windowsEvents)
        .filter(([_, event]) => event.mitre.length > 0);
    renderWinEvents(filtered);
    setWinFilterActive(btn);
};

window.showAllWinEvents = function () {
    document.getElementById('winEventSearch').value = '';
    document.getElementById('winCategoryFilter').value = 'all';
    document.getElementById('winLogFilter').value = 'all';
    renderAllWinEvents();
    setWinFilterActive(null); // clear glow on all filters
};

        function renderAllWinEvents() {
            renderWinEvents(Object.entries(windowsEvents));
        }

        function renderWinEvents(events) {
            const container = document.getElementById('winEventsContainer');

            if (events.length === 0) {
                container.innerHTML = '<div class="alert alert-warning">No events found matching your criteria</div>';
                return;
            }

            const sortedEvents = events.sort((a, b) => parseInt(a[0]) - parseInt(b[0]));

            container.innerHTML = `
                <div class="alert alert-secondary mb-2 py-2">
                    <small>Showing <strong>${events.length}</strong> event${events.length !== 1 ? 's' : ''}</small>
                </div>
                <div class="row g-2">
                    ${sortedEvents.map(([id, event]) => `
                        <div class="col-12 col-md-6 col-xl-4">
                            <div class="card h-100 win-event-card ${event.severity}">
                                <div class="card-body p-2">
                                    <div class="d-flex justify-content-between align-items-start mb-1">
                                        <div>
                                            <span class="badge bg-${event.severity === 'danger' ? 'danger' : event.severity === 'warning' ? 'warning text-dark' : 'info text-dark'} me-1">${id}</span>
                                            <span class="badge bg-secondary badge-sm">${event.logName}</span>
                                        </div>
                                        <button class="btn btn-sm btn-outline-secondary py-0 px-1" onclick="copyWinEventQuery(${id}, '${event.logName}')" title="Copy Query">
                                            <i class="bi bi-clipboard"></i>
                                        </button>
                                    </div>
                                    
                                    <h6 class="mb-1 small">${event.name}</h6>
                                    <p class="small text-secondary mb-2" style="font-size: 0.75rem;">${event.description}</p>
                                    
                                    <div class="mb-1" style="font-size: 0.7rem;">
                                        <strong>Category:</strong> <span class="badge bg-dark badge-sm">${event.category}</span>
                                    </div>
                                    
                                    <div class="mb-1" style="font-size: 0.7rem;">
                                        <strong>Use Case:</strong><br>
                                        <span class="text-info">${event.useCase}</span>
                                    </div>
                                    
                                    <div class="mb-1" style="font-size: 0.65rem;">
                                        <strong>Key Fields:</strong><br>
                                        ${event.keyFields.map(field => `<code class="text-warning">${field}</code>`).join(', ')}
                                    </div>
                                    
                                    ${event.mitre.length > 0 ? `
                                        <div class="mb-1" style="font-size: 0.65rem;">
                                            <strong>MITRE ATT&CK:</strong>
                                            ${event.mitre.map(t => `<span class="badge bg-danger badge-sm">${t}</span>`).join(' ')}
                                        </div>
                                    ` : ''}
                                    
                                    <div style="font-size: 0.7rem;">
                                        <strong>💡 Tips:</strong><br>
                                        <span class="text-muted">${event.detectionTips}</span>
                                    </div>
                                </div>
                            </div>
                        </div>
                    `).join('')}
                </div>

                  
            `;
        }

        function showWinToast(message) {
            const toast = document.createElement('div');
            toast.className = 'alert alert-success position-fixed top-0 start-50 translate-middle-x mt-3';
            toast.style.zIndex = '9999';
            toast.innerHTML = `<i class="bi bi-check-circle-fill"></i> ${message}`;
            document.body.appendChild(toast);
            setTimeout(() => toast.remove(), 2000);
        }
    }

    // Register the tool
    window.registerCyberSuiteTool({
        id: 'windows-event-reference',
        name: 'Windows Event ID Reference',
        description: 'Complete reference for Windows Security and System event IDs with MITRE ATT&CK mappings',
        icon: 'bi-shield-check',
        category: 'blue',
        render: render,
        init: init
    });
})();