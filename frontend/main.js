/**
 * VULNAUDIT WARFARE — Terminal Controller
 * With Data-Reaper Credential Dump Renderer
 */

(function() {
    'use strict';

    const $ = id => document.getElementById(id);

    const targetInput = $('target-url');
    const launchBtn   = $('launch-btn');
    const stopBtn     = $('stop-btn');
    const clearBtn    = $('clear-btn');
    const terminal    = $('terminal');
    const statusText  = $('status-text');
    const statusSub   = $('status-sub');
    const statusRing  = $('status-ring');
    const sqlmapText  = $('sqlmap-text');
    const elapsedDisp = $('elapsed-time');
    const targetDisp  = $('target-display');
    const threatText  = $('threat-text');
    const cursorRow   = $('term-cursor-row');
    const dumpArea    = $('data-dump-area');

    let isScanning = false;
    let pollInterval = null;
    let elapsedInterval = null;
    let scanStartTime = null;
    let lastOutputIndex = 0;

    const STATES = {
        'IDLE':           { text: 'IDLE',          sub: 'Standby mode engaged',      ring: 'sr-idle',              color: '#1a1a1a',  threat: 'MINIMAL' },
        'SCANNING':       { text: 'SCANNING',      sub: 'Active enumeration',        ring: 'sr-scanning',          color: '#ffaa00',  threat: 'ELEVATED' },
        'VULNERABLE':     { text: 'VULNERABLE',    sub: 'Exploit vector confirmed',  ring: 'sr-vulnerable',        color: '#ff003c',  threat: 'CRITICAL' },
        'NOT_VULNERABLE': { text: 'HARDENED',      sub: 'No vectors detected',       ring: 'sr-not-vulnerable',    color: '#00ff41',  threat: 'NONE' },
        'ERROR':          { text: 'ERROR',         sub: 'Execution failure',         ring: 'sr-error',             color: '#ff003c',  threat: 'UNKNOWN' },
        'COMPLETED':      { text: 'COMPLETED',     sub: 'Audit sequence finished',   ring: 'sr-completed',         color: '#00f0ff',  threat: 'LOW' }
    };

    function init() {
        checkHealth();
        bindEvents();
        checkExisting();
        setInterval(checkHealth, 30000);
    }

    function bindEvents() {
        launchBtn.addEventListener('click', startAudit);
        stopBtn.addEventListener('click', stopAudit);
        clearBtn.addEventListener('click', clearTerm);
        targetInput.addEventListener('keypress', e => { if (e.key === 'Enter') startAudit(); });
    }

    // ============================================
    // API
    // ============================================

    async function checkHealth() {
        try {
            const res = await fetch('/api/health');
            const data = await res.json();
            if (data.sqlmap_available) {
                sqlmapText.textContent = 'ONLINE';
                sqlmapText.style.color = 'var(--neon-green)';
                sqlmapText.style.textShadow = 'var(--green-glow)';
            } else {
                sqlmapText.textContent = 'OFFLINE';
                sqlmapText.style.color = 'var(--blood)';
                sqlmapText.style.textShadow = 'var(--blood-glow)';
                log('system', '[!] sqlmap binary not found. Run: sudo apt install sqlmap');
            }
        } catch {
            sqlmapText.textContent = 'UNKNOWN';
            sqlmapText.style.color = '#333';
            sqlmapText.style.textShadow = 'none';
        }
    }

    async function checkExisting() {
        try {
            const res = await fetch('/api/audit_status');
            const data = await res.json();
            if (data.status === 'SCANNING') {
                isScanning = true;
                scanStartTime = data.start_time ? new Date(data.start_time).getTime() : Date.now();
                setUI(true);
                setStatus('SCANNING');
                targetDisp.textContent = (data.target_url || 'NONE').toUpperCase();
                cursorRow.style.display = 'flex';
                if (data.output?.length) {
                    data.output.forEach(l => log(l.type || 'normal', l.text, l.timestamp));
                    lastOutputIndex = data.output.length;
                }
                if (data.extracted_data?.length) {
                    renderDump(data.extracted_data);
                }
                log('system', '[*] Reconnected to active audit session.');
                startPoll();
                startTimer();
            }
        } catch (e) {
            console.error('Reconnect failed:', e);
        }
    }

    async function startAudit() {
        const url = targetInput.value.trim();
        if (!url) { log('error', '[!] Enter target URL.'); return; }
        if (!url.startsWith('http://') && !url.startsWith('https://')) {
            log('error', '[!] Protocol required: http:// or https://'); return;
        }

        clearTerm();
        clearDump();
        isScanning = true;
        lastOutputIndex = 0;
        scanStartTime = Date.now();

        setUI(true);
        setStatus('SCANNING');
        targetDisp.textContent = url.toUpperCase();
        cursorRow.style.display = 'flex';

        log('system', `[*] Initializing vector: ${url}`);
        log('system', '[*] Handing off to sqlmap engine...');

        try {
            const res = await fetch('/api/start_audit', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target_url: url })
            });
            const data = await res.json();

            if (!data.success) {
                log('error', `[!] ${data.error}`);
                setStatus('ERROR');
                resetUI();
                return;
            }

            log('info', `[*] ${data.message}`);
            startPoll();
            startTimer();

        } catch (err) {
            log('critical', `[!] Network failure: ${err.message}`);
            setStatus('ERROR');
            resetUI();
        }
    }

    async function stopAudit() {
        try {
            log('warning', '[*] Sending abort signal...');
            const res = await fetch('/api/stop_audit', { method: 'POST' });
            const data = await res.json();
            if (data.success) {
                log('info', `[*] ${data.message}`);
                resetUI();
            } else {
                log('error', `[!] ${data.error}`);
            }
        } catch (err) {
            log('error', `[!] Abort failed: ${err.message}`);
        }
    }

    // ============================================
    // POLLING
    // ============================================

    function startPoll() {
        if (pollInterval) clearInterval(pollInterval);
        pollInterval = setInterval(pollStatus, 2000);
    }

    function stopPoll() {
        if (pollInterval) { clearInterval(pollInterval); pollInterval = null; }
    }

    async function pollStatus() {
        try {
            const res = await fetch('/api/audit_status');
            const data = await res.json();

            if (data.status && STATES[data.status]) setStatus(data.status);
            if (data.target_url) targetDisp.textContent = data.target_url.toUpperCase();

            if (data.output?.length > lastOutputIndex) {
                data.output.slice(lastOutputIndex).forEach(l => log(l.type || 'normal', l.text, l.timestamp));
                lastOutputIndex = data.output.length;
            }

            // Render extracted credential data when available
            if (data.extracted_data?.length > 0) {
                renderDump(data.extracted_data);
            }

            if (data.status !== 'SCANNING' && isScanning) {
                isScanning = false;
                resetUI();

                if (data.status === 'VULNERABLE') {
                    log('critical', '[!] THREAT CONFIRMED: SQL injection vector successful.');
                    log('critical', '[!] Database enumeration complete. Immediate patch required.');
                } else if (data.status === 'NOT_VULNERABLE') {
                    log('success', '[*] Target hardened. No injectable parameters found.');
                } else if (data.status === 'ERROR') {
                    log('error', '[!] Operation terminated with errors.');
                } else {
                    log('info', '[*] Operation sequence complete.');
                }
            }
        } catch (e) {
            console.error('Poll error:', e);
        }
    }

    // ============================================
    // DATA DUMP RENDERER
    // ============================================

    function renderDump(tables) {
        if (!tables || tables.length === 0) return;

        dumpArea.innerHTML = '';

        tables.forEach((table, idx) => {
            const container = document.createElement('div');
            container.className = 'dump-table-wrap';

            const title = document.createElement('div');
            title.className = 'dump-title';
            title.textContent = `> TABLE: ${table.table_name} [${table.rows.length} ROWS]`;
            container.appendChild(title);

            if (table.rows.length === 0) {
                const empty = document.createElement('div');
                empty.className = 'dump-empty';
                empty.textContent = 'Empty table.';
                container.appendChild(empty);
                dumpArea.appendChild(container);
                return;
            }

            const tbl = document.createElement('table');
            tbl.className = 'dump-table';

            // Header
            const thead = document.createElement('thead');
            const hr = document.createElement('tr');
            Object.keys(table.rows[0]).forEach(col => {
                const th = document.createElement('th');
                th.textContent = col;
                hr.appendChild(th);
            });
            thead.appendChild(hr);
            tbl.appendChild(thead);

            // Body
            const tbody = document.createElement('tbody');
            table.rows.forEach(row => {
                const tr = document.createElement('tr');
                Object.values(row).forEach(val => {
                    const td = document.createElement('td');
                    td.textContent = val || 'NULL';
                    tr.appendChild(td);
                });
                tbody.appendChild(tr);
            });
            tbl.appendChild(tbody);

            container.appendChild(tbl);
            dumpArea.appendChild(container);
        });
    }

    function clearDump() {
        dumpArea.innerHTML = '<div class="dump-empty">No data extracted yet.</div>';
    }

    // ============================================
    // UI HELPERS
    // ============================================

    function setStatus(key) {
        const s = STATES[key] || STATES['IDLE'];
        statusText.textContent = s.text;
        statusText.style.color = s.color;
        statusText.style.textShadow = `0 0 8px ${s.color}40`;
        statusSub.textContent = s.sub;
        statusRing.className = 'sw-ring ' + s.ring;
        threatText.textContent = s.threat;
        threatText.style.color = s.color;
        threatText.style.textShadow = `0 0 6px ${s.color}40`;
    }

    function setUI(scanning) {
        launchBtn.disabled = scanning;
        stopBtn.disabled = !scanning;
        targetInput.disabled = scanning;
    }

    function resetUI() {
        stopPoll();
        stopTimer();
        setUI(false);
        cursorRow.style.display = 'none';
    }

    function log(type, text, timestamp) {
        const line = document.createElement('div');
        line.className = 't-row t-' + type;
        const t = timestamp || new Date().toTimeString().slice(0, 8);
        line.innerHTML = `<span class="t-ts">${t}</span><span class="t-tx">${esc(text)}</span>`;
        terminal.appendChild(line);
        terminal.scrollTop = terminal.scrollHeight;
    }

    function esc(s) {
        const d = document.createElement('div');
        d.textContent = s;
        return d.innerHTML;
    }

    function clearTerm() {
        terminal.innerHTML = '';
        log('system', '[*] Buffer purged.');
    }

    function startTimer() {
        if (elapsedInterval) clearInterval(elapsedInterval);
        elapsedInterval = setInterval(() => {
            if (!scanStartTime) return;
            const sec = Math.floor((Date.now() - scanStartTime) / 1000);
            const h = String(Math.floor(sec / 3600)).padStart(2, '0');
            const m = String(Math.floor((sec % 3600) / 60)).padStart(2, '0');
            const s = String(sec % 60).padStart(2, '0');
            elapsedDisp.textContent = `${h}:${m}:${s}`;
        }, 1000);
    }

    function stopTimer() {
        if (elapsedInterval) { clearInterval(elapsedInterval); elapsedInterval = null; }
    }

    document.addEventListener('DOMContentLoaded', init);

})();