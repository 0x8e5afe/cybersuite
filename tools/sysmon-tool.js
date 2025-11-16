// ========================================
// SYSMON EVENT ID REFERENCE
// Category: Blue Team
// ========================================

(function() {
    'use strict';

    const sysmonEvents = {
        1: {
            name: 'Process Creation',
            description: 'Process created with full command line',
            useCase: 'Track malicious process execution, living-off-the-land binaries',
            keyFields: ['CommandLine', 'ParentImage', 'User', 'Hashes', 'ParentCommandLine'],
            detectionTips: 'Monitor for unusual parent-child relationships, encoded commands, suspicious paths',
            severity: 'info',
            category: 'Process Activity'
        },
        2: {
            name: 'File Creation Time Changed',
            description: 'File creation time was explicitly modified',
            useCase: 'Detect timestomping and anti-forensics techniques',
            keyFields: ['Image', 'TargetFilename', 'CreationUtcTime', 'PreviousCreationUtcTime'],
            detectionTips: 'Look for modifications to system files or executables in suspicious locations',
            severity: 'warning',
            category: 'File Activity'
        },
        3: {
            name: 'Network Connection',
            description: 'Network connection initiated or received',
            useCase: 'Track C2 communications, lateral movement, data exfiltration',
            keyFields: ['DestinationIp', 'DestinationPort', 'Image', 'User', 'DestinationHostname'],
            detectionTips: 'Monitor for connections to suspicious IPs, unusual ports, or known bad domains',
            severity: 'warning',
            category: 'Network Activity'
        },
        4: {
            name: 'Sysmon Service State Changed',
            description: 'Sysmon service state change detected',
            useCase: 'Detect tampering with Sysmon monitoring',
            keyFields: ['State', 'Version', 'SchemaVersion'],
            detectionTips: 'Alert on any Sysmon service stops or configuration changes',
            severity: 'danger',
            category: 'Service Activity'
        },
        5: {
            name: 'Process Terminated',
            description: 'Process terminated',
            useCase: 'Track process lifecycle and detect defense evasion',
            keyFields: ['Image', 'ProcessId', 'User'],
            detectionTips: 'Correlate with Event ID 1 to understand process behavior patterns',
            severity: 'info',
            category: 'Process Activity'
        },
        6: {
            name: 'Driver Loaded',
            description: 'Driver loaded into kernel',
            useCase: 'Detect rootkits and malicious kernel drivers',
            keyFields: ['ImageLoaded', 'Signature', 'SignatureStatus', 'Signed'],
            detectionTips: 'Alert on unsigned drivers or drivers from non-standard locations',
            severity: 'warning',
            category: 'Driver Activity'
        },
        7: {
            name: 'Image Loaded',
            description: 'DLL or executable image loaded',
            useCase: 'Detect DLL injection, process hollowing, reflective loading',
            keyFields: ['ImageLoaded', 'Image', 'Signature', 'SignatureStatus'],
            detectionTips: 'Monitor for unsigned DLLs, unusual loading patterns, or injection techniques',
            severity: 'info',
            category: 'Process Activity'
        },
        8: {
            name: 'CreateRemoteThread',
            description: 'Remote thread created in another process',
            useCase: 'Detect process injection and code injection techniques',
            keyFields: ['SourceImage', 'TargetImage', 'StartAddress', 'StartFunction'],
            detectionTips: 'High confidence indicator of process injection - investigate immediately',
            severity: 'danger',
            category: 'Process Activity'
        },
        9: {
            name: 'RawAccessRead',
            description: 'Raw access to drive data detected',
            useCase: 'Detect credential dumping and disk forensics tools',
            keyFields: ['Image', 'Device'],
            detectionTips: 'Monitor for access to disk volumes or physical drives by non-system processes',
            severity: 'danger',
            category: 'File Activity'
        },
        10: {
            name: 'ProcessAccess',
            description: 'Process accessed another process',
            useCase: 'Detect credential dumping (LSASS access), process manipulation',
            keyFields: ['SourceImage', 'TargetImage', 'GrantedAccess', 'CallTrace'],
            detectionTips: 'Alert on LSASS access, especially with PROCESS_VM_READ rights',
            severity: 'danger',
            category: 'Process Activity'
        },
        11: {
            name: 'FileCreate',
            description: 'File created or overwritten',
            useCase: 'Track malware dropper activity, persistence mechanisms',
            keyFields: ['Image', 'TargetFilename', 'CreationUtcTime'],
            detectionTips: 'Monitor startup folders, temp directories, and user profile paths',
            severity: 'info',
            category: 'File Activity'
        },
        12: {
            name: 'RegistryEvent (Object create/delete)',
            description: 'Registry key or value created or deleted',
            useCase: 'Detect persistence mechanisms and configuration changes',
            keyFields: ['Image', 'TargetObject', 'EventType'],
            detectionTips: 'Focus on Run keys, Services, and other persistence locations',
            severity: 'warning',
            category: 'Registry Activity'
        },
        13: {
            name: 'RegistryEvent (Value Set)',
            description: 'Registry value modification',
            useCase: 'Track configuration changes and persistence',
            keyFields: ['Image', 'TargetObject', 'Details'],
            detectionTips: 'Monitor autorun locations and security settings modifications',
            severity: 'warning',
            category: 'Registry Activity'
        },
        14: {
            name: 'RegistryEvent (Key/Value Rename)',
            description: 'Registry key or value renamed',
            useCase: 'Detect registry-based persistence and configuration tampering',
            keyFields: ['Image', 'TargetObject', 'NewName'],
            detectionTips: 'Look for suspicious renames in critical registry paths',
            severity: 'warning',
            category: 'Registry Activity'
        },
        15: {
            name: 'FileCreateStreamHash',
            description: 'Alternate data stream created',
            useCase: 'Detect data hiding in alternate data streams',
            keyFields: ['Image', 'TargetFilename', 'Hash'],
            detectionTips: 'Alert on ADS creation in executable directories or system folders',
            severity: 'warning',
            category: 'File Activity'
        },
        16: {
            name: 'ServiceConfigurationChange',
            description: 'Sysmon configuration changed',
            useCase: 'Detect tampering with Sysmon monitoring rules',
            keyFields: ['Configuration', 'ConfigurationFileHash'],
            detectionTips: 'Alert immediately - may indicate attacker trying to evade detection',
            severity: 'danger',
            category: 'Service Activity'
        },
        17: {
            name: 'PipeEvent (Pipe Created)',
            description: 'Named pipe created',
            useCase: 'Detect C2 communications and inter-process communication',
            keyFields: ['Image', 'PipeName'],
            detectionTips: 'Monitor for suspicious pipe names used by common malware',
            severity: 'info',
            category: 'Network Activity'
        },
        18: {
            name: 'PipeEvent (Pipe Connected)',
            description: 'Named pipe connection detected',
            useCase: 'Track named pipe-based IPC and C2',
            keyFields: ['Image', 'PipeName'],
            detectionTips: 'Correlate with Event ID 17 to identify suspicious pipe usage',
            severity: 'info',
            category: 'Network Activity'
        },
        19: {
            name: 'WmiEvent (WmiEventFilter)',
            description: 'WMI event filter activity',
            useCase: 'Detect WMI-based persistence and lateral movement',
            keyFields: ['EventNamespace', 'Name', 'Query'],
            detectionTips: 'WMI persistence is common in APT attacks - high priority',
            severity: 'danger',
            category: 'WMI Activity'
        },
        20: {
            name: 'WmiEvent (WmiEventConsumer)',
            description: 'WMI event consumer activity',
            useCase: 'Detect WMI-based persistence mechanisms',
            keyFields: ['Name', 'Type', 'Destination'],
            detectionTips: 'Alert on CommandLineEventConsumer with suspicious commands',
            severity: 'danger',
            category: 'WMI Activity'
        },
        21: {
            name: 'WmiEvent (WmiEventConsumerToFilter)',
            description: 'WMI consumer bound to filter',
            useCase: 'Detect complete WMI persistence setup',
            keyFields: ['Consumer', 'Filter'],
            detectionTips: 'This completes WMI persistence - investigate immediately',
            severity: 'danger',
            category: 'WMI Activity'
        },
        22: {
            name: 'DNSEvent (DNS query)',
            description: 'DNS query recorded',
            useCase: 'Detect C2 via DNS, DNS tunneling, domain generation algorithms',
            keyFields: ['Image', 'QueryName', 'QueryResults'],
            detectionTips: 'Monitor for suspicious TLDs, long subdomains, high entropy domains',
            severity: 'warning',
            category: 'Network Activity'
        },
        23: {
            name: 'FileDelete',
            description: 'File deletion detected',
            useCase: 'Detect anti-forensics and log deletion',
            keyFields: ['Image', 'TargetFilename', 'User'],
            detectionTips: 'Alert on deletion of security logs or in system directories',
            severity: 'warning',
            category: 'File Activity'
        },
        24: {
            name: 'ClipboardChange',
            description: 'Clipboard content changed',
            useCase: 'Detect clipboard hijacking and sensitive data theft',
            keyFields: ['Image', 'Session', 'ClientInfo'],
            detectionTips: 'Monitor for clipboard access by unusual processes',
            severity: 'info',
            category: 'Process Activity'
        },
        25: {
            name: 'ProcessTampering',
            description: 'Process image tampering detected',
            useCase: 'Detect process hollowing and image manipulation',
            keyFields: ['Image', 'Type'],
            detectionTips: 'High confidence indicator of process injection techniques',
            severity: 'danger',
            category: 'Process Activity'
        },
        26: {
            name: 'FileDeleteDetected',
            description: 'File delete operations logged',
            useCase: 'Track file deletions for forensic analysis',
            keyFields: ['Image', 'TargetFilename', 'User'],
            detectionTips: 'Useful for forensic timeline reconstruction',
            severity: 'info',
            category: 'File Activity'
        },
        27: {
            name: 'FileBlockExecutable',
            description: 'File block executable detected',
            useCase: 'Track blocked executable files',
            keyFields: ['Image', 'TargetFilename'],
            detectionTips: 'Review blocked executables for potential threats',
            severity: 'warning',
            category: 'File Activity'
        },
        28: {
            name: 'FileBlockShredding',
            description: 'File shredding detected',
            useCase: 'Detect secure file deletion attempts',
            keyFields: ['Image', 'TargetFilename'],
            detectionTips: 'May indicate anti-forensics activity',
            severity: 'warning',
            category: 'File Activity'
        },
        29: {
            name: 'FileExecutableDetected',
            description: 'Executable file detected',
            useCase: 'Track new executable files',
            keyFields: ['Image', 'TargetFilename', 'Hashes'],
            detectionTips: 'Monitor for executables in unusual locations',
            severity: 'info',
            category: 'File Activity'
        }
    };

    const categories = [...new Set(Object.values(sysmonEvents).map(e => e.category))];

    function render() {
        return `
                        <div class="section-header">
                <h3 class="mb-1 d-flex align-items-center gap-2">
                    <i class="bi bi-windows"></i>
                    <span>Sysmon Event ID Reference</span>
                </h3>
                <p class="text-secondary mb-0">
                  Quick reference for Windows Sysmon event IDs and detection use cases.
                </p>
            </div>
            
            <div class="row g-3 mb-3">
                <div class="col-md-6">
                    <label for="eventIdSearch" class="form-label small">Search by Event ID or Name</label>
                    <input type="text" class="form-control form-control-sm" id="eventIdSearch" placeholder="e.g., 1, Process Creation, network...">
                </div>
                <div class="col-md-6">
                    <label for="categoryFilter" class="form-label small">Filter by Category</label>
                    <select class="form-select form-select-sm" id="categoryFilter">
                        <option value="all">All Categories</option>
                        ${categories.map(cat => `<option value="${cat}">${cat}</option>`).join('')}
                    </select>
                </div>
            </div>

            <div class="mb-3">
               <div class="btn-group btn-group-sm" role="group">
    <button class="btn btn-outline-danger sysmon-filter-btn"
            type="button"
            onclick="filterSysmonBySeverity('danger', this)">
        <i class="bi bi-exclamation-triangle-fill"></i> Critical
    </button>
    <button class="btn btn-outline-warning sysmon-filter-btn"
            type="button"
            onclick="filterSysmonBySeverity('warning', this)">
        <i class="bi bi-exclamation-circle-fill"></i> Warning
    </button>
    <button class="btn btn-outline-info sysmon-filter-btn"
            type="button"
            onclick="filterSysmonBySeverity('info', this)">
        <i class="bi bi-info-circle-fill"></i> Info
    </button>
    <button class="btn btn-outline-secondary"
            type="button"
            onclick="showAllEvents()">
        <i class="bi bi-arrow-counterclockwise"></i> Show All
    </button>
</div>
            </div>
            
            <div id="sysmonEventsContainer"></div>
        `;
    }

    function init() {
        // Initial render
        renderAllEvents();

        // Search functionality
        document.getElementById('eventIdSearch').addEventListener('input', function() {
            const query = this.value.toLowerCase();
            filterEvents(query, document.getElementById('categoryFilter').value);
        });

        // Category filter
        document.getElementById('categoryFilter').addEventListener('change', function() {
            const query = document.getElementById('eventIdSearch').value.toLowerCase();
            filterEvents(query, this.value);
        });

function setSysmonFilterActive(btn) {
    document.querySelectorAll('.sysmon-filter-btn')
        .forEach(b => b.classList.remove('active'));
    if (btn) {
        btn.classList.add('active');
    }
}


window.filterSysmonBySeverity = function (severity, btn) {
    const filtered = Object.entries(sysmonEvents)
        .filter(([_, event]) => event.severity === severity);
    renderEvents(filtered);
    setSysmonFilterActive(btn);
};

window.showAllEvents = function () {
    document.getElementById('eventIdSearch').value = '';
    document.getElementById('categoryFilter').value = 'all';
    renderAllEvents();
    setSysmonFilterActive(null); // clear glow when showing all
};

        window.copyEventQuery = function(eventId) {
            const query = `Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; ID=${eventId}} -MaxEvents 100`;
            navigator.clipboard.writeText(query).then(() => {
                showToast('PowerShell query copied to clipboard!');
            });
        };

        function filterEvents(query, category) {
            let filtered = Object.entries(sysmonEvents);

            if (query) {
                filtered = filtered.filter(([id, event]) => 
                    id.includes(query) ||
                    event.name.toLowerCase().includes(query) ||
                    event.description.toLowerCase().includes(query) ||
                    event.useCase.toLowerCase().includes(query)
                );
            }

            if (category !== 'all') {
                filtered = filtered.filter(([_, event]) => event.category === category);
            }

            renderEvents(filtered);
        }

        function renderAllEvents() {
            renderEvents(Object.entries(sysmonEvents));
        }

        function renderEvents(events) {
            const container = document.getElementById('sysmonEventsContainer');
            
            if (events.length === 0) {
                container.innerHTML = '<div class="alert alert-warning">No events found matching your criteria</div>';
                return;
            }

            container.innerHTML = `
                <div class="row g-2">
                    ${events.map(([id, event]) => `
                        <div class="col-12 col-md-6 col-lg-4">
                            <div class="card h-100 sysmon-event-card ${event.severity}">
                                <div class="card-body p-2">
                                    <div class="d-flex justify-content-between align-items-start mb-2">
                                        <h6 class="mb-0">
                                            <span class="badge bg-${event.severity === 'danger' ? 'danger' : event.severity === 'warning' ? 'warning' : 'info'}">${id}</span>
                                            ${event.name}
                                        </h6>
                                        <button class="btn btn-sm btn-outline-secondary py-0 px-1" onclick="copyEventQuery(${id})" title="Copy PowerShell Query">
                                            <i class="bi bi-clipboard"></i>
                                        </button>
                                    </div>
                                    
                                    <p class="small text-secondary mb-2">${event.description}</p>
                                    
                                    <div class="small mb-2">
                                        <strong>Category:</strong> <span class="badge bg-secondary badge-sm">${event.category}</span>
                                    </div>
                                    
                                    <div class="small mb-2">
                                        <strong>Use Case:</strong><br>
                                        <span class="text-info">${event.useCase}</span>
                                    </div>
                                    
                                    <div class="small mb-2">
                                        <strong>Key Fields:</strong><br>
                                        ${event.keyFields.map(field => `<code class="text-warning" style="font-size: 0.7rem;">${field}</code>`).join(', ')}
                                    </div>
                                    
                                    <div class="small">
                                        <strong>💡 Detection Tips:</strong><br>
                                        <span class="text-muted">${event.detectionTips}</span>
                                    </div>
                                </div>
                            </div>
                        </div>
                    `).join('')}
                </div>
                
                <div class="alert alert-info mt-3">
                    <small>
                        <strong><i class="bi bi-lightbulb"></i> Pro Tip:</strong> 
                        Click the <i class="bi bi-clipboard"></i> icon to copy a PowerShell query for retrieving that specific event type.
                    </small>
                </div>
            `;
        }

        function showToast(message) {
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
        id: 'sysmon-event-reference',
        name: 'Sysmon Event ID Reference',
        description: 'Complete reference for Windows Sysmon event IDs with detection use cases and key fields',
        icon: 'bi-windows',
        category: 'blue',
        render: render,
        init: init
    });
})();