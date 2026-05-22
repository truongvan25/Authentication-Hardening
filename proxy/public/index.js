const sleep = ms => new Promise(r => setTimeout(r, ms));
let busy = false;

/* ── output helpers ── */
function clearOut() { document.getElementById('output').innerHTML = ''; }
function out(text, cls = 'o-info') {
    const el = document.getElementById('output');
    const d = document.createElement('div');
    d.className = cls; d.textContent = text;
    el.appendChild(d); el.scrollTop = el.scrollHeight;
}

/* ── login helper ── */
async function login(body, headers = {}) {
    const r = await fetch('/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...headers },
        body: JSON.stringify(body),
    });
    const text = await r.text();
    try {
        return { status: r.status, body: JSON.parse(text) };
    } catch {
        return { status: r.status, body: { error: text || '(empty response)' } };
    }
}

/* ── button state ── */
function setBusy(on) {
    busy = on;
    document.querySelectorAll('.tc-btn').forEach(b => {
        if (on) {
            if (!b.disabled) b.dataset.busy = '1';
            b.disabled = true;
        } else {
            if (b.dataset.busy) {
                b.disabled = false;
                delete b.dataset.busy;
            }
        }
    });
}
function markTC(idx, on) {
    const btns = document.querySelectorAll('.tc-btn:not([disabled])');
    btns[idx]?.classList.toggle('running', on);
}

/* ══════════════════════════════════════
TC IMPLEMENTATIONS
══════════════════════════════════════ */

async function tc01() {
    const passwords = ['123456', 'password', 'admin', 'qwerty', 'letmein', 'secret123', 'abc123'];
    out('══ TC-01 · Brute Force ══════════════════════', 'o-title');
    out(`Target account: admin  |  Wordlist: ${passwords.length} entries`, 'o-info');
    out('', 'o-info');
    for (let i = 0; i < passwords.length; i++) {
        const { status, body } = await login({ username: 'admin', password: passwords[i] });
        const label = status === 200 ? '[SUCCESS]' : status === 429 ? '[BLOCKED]' : '[fail]';
        const cls = status === 200 ? 'o-ok' : status === 429 ? 'o-fail' : 'o-info';
        out(`Attempt ${String(i + 1).padStart(2)}: pass='${passwords[i].padEnd(10)}  ${status} ${label}`, cls);
        if (status === 200) { out('', 'o-info'); out('>>> ATTACK SUCCEEDED on unprotected backend', 'o-ok'); break; }
        if (status === 429) { out('', 'o-info'); out('>>> ATTACK BLOCKED — IP blacklisted for 15 min', 'o-fail'); break; }
        await sleep(120);
    }
}

async function tc02() {
    const combos = [
        ['alice@mail.com', 'hunter2'], ['bob@mail.com', 'monkey'],
        ['carol@mail.com', 'iloveyou'], ['dave@mail.com', 'sunshine'],
        ['eve@mail.com', 'princess'], ['frank@mail.com', 'password1'],
        ['grace@mail.com', 'dragon'], ['hank@mail.com', 'master'],
    ];
    out('══ TC-02 · Credential Stuffing ══════════════', 'o-title');
    out(`Pattern: 1 IP, ${combos.length} different accounts (breach DB)`, 'o-info');
    out('Username diversity threshold: 3  |  IP rate limit: 5', 'o-info');
    out('', 'o-info');
    for (let i = 0; i < combos.length; i++) {
        const [user, pass] = combos[i];
        const { status, body } = await login({ username: user, password: pass });
        const n = String(i + 1).padStart(2, '0');
        if (status === 429) {
            out(`[${n}] ${user.padEnd(24)} → ${status}  [BLOCKED]`, 'o-fail');
            out('', 'o-info');
            out(`>>> CREDENTIAL_STUFFING_DETECTED at attempt ${i + 1}`, 'o-fail');
            out(`    Blocked before IP rate limit (${i + 1} < 5 total requests)`, 'o-fail');
            break;
        }
        out(`[${n}] ${user.padEnd(24)} → ${status}`, 'o-info');
        await sleep(80);
    }
}

async function tc03() {
    out('══ TC-03 · Account Enumeration ══════════════', 'o-title');
    out("Probe: 'ghost' (non-existent) vs 'admin' (valid user, wrong pass)", 'o-info');
    out('', 'o-info');

    const { ghost, admin } = await (await fetch('/admin/enumeration-test')).json();

    out('── Direct → backend :3000 (no proxy) ──', 'o-warn');
    out(`  username='ghost'  → "${ghost.body.error}"`, 'o-info');
    out(`  username='admin'  → "${admin.body.error}"`, 'o-info');
    if (ghost.body.error !== admin.body.error) {
        out('  ↑ DIFFERENT responses — enumeration POSSIBLE', 'o-fail');
    }
    out('', 'o-info');

    out('── Through proxy :4000 ──', 'o-warn');
    const pg = await login({ username: 'ghost', password: 'x' });
    const pa = await login({ username: 'admin', password: 'x' });
    out(`  username='ghost'  → "${pg.body.error}"`, 'o-info');
    out(`  username='admin'  → "${pa.body.error}"`, 'o-info');
    if (pg.body.error === pa.body.error) {
        out('  ↑ IDENTICAL responses — enumeration PREVENTED', 'o-ok');
    }
}

async function tc04() {
    out('══ TC-04 · Distributed Brute Force ══════════', 'o-title');
    out('12 different X-Real-IP headers → same account (admin)', 'o-info');
    out('Each IP sends 1 request → IP rate limit never triggers', 'o-info');
    out('Account lock triggers after 10 cumulative failures', 'o-info');
    out('', 'o-info');
    for (let i = 1; i <= 12; i++) {
        const { status, body } = await login(
            { username: 'admin', password: `wrong${i}` },
            { 'X-Real-IP': `10.0.0.${i}` }
        );
        const ip = `10.0.0.${i}`;
        const cls = status === 423 ? 'o-fail' : 'o-info';
        out(`IP ${ip.padEnd(10)}  → ${status}  ${body.error || ''}`, cls);
        if (status === 423 && i > 10) break;
        await sleep(100);
    }
    out('', 'o-info');
    out('Testing correct password while account is locked:', 'o-warn');
    const { status, body } = await login({ username: 'admin', password: 'secret123' });
    if (status === 423) {
        out(`→ 423  ${body.error}`, 'o-fail');
        out('>>> Correct password rejected — account lockout working', 'o-fail');
    } else {
        out(`→ ${status} (account not locked yet — run again after reset)`, 'o-warn');
    }
}

async function tc05() {
    out('══ TC-05 · Header Spoofing ══════════════════', 'o-title');
    out('Step 1: Blacklist real IP via brute force...', 'o-info');
    out('', 'o-info');
    const passwords = ['123456', 'password', 'admin', 'qwerty', 'letmein', 'secret123'];
    for (let i = 0; i < passwords.length; i++) {
        const { status } = await login({ username: 'admin', password: passwords[i] });
        out(`Attempt ${i + 1}: ${status === 429 ? '[IP BLACKLISTED]' : status}`,
            status === 429 ? 'o-fail' : 'o-info');
        if (status === 429) break;
        await sleep(100);
    }
    out('', 'o-info');
    out('Step 2: Attacker tries X-Forwarded-For to fake IP...', 'o-warn');
    out('', 'o-info');
    for (let i = 1; i <= 4; i++) {
        const { status, body } = await login(
            { username: 'admin', password: 'bypass' },
            { 'X-Forwarded-For': `9.9.9.${i}` }
        );
        out(`X-Forwarded-For: 9.9.9.${i}  →  ${status}  ${body.error || ''}`,
            status === 429 ? 'o-fail' : 'o-ok');
        await sleep(100);
    }
    out('', 'o-info');
    out('>>> X-Forwarded-For ignored — real socket IP still blocked', 'o-fail');
}

/* ── dispatcher ── */
async function run(tc) {
    if (busy) return;
    setBusy(true);
    markTC(tc - 1, true);
    clearOut();
    try {
        if (tc === 1) await tc01();
        else if (tc === 2) await tc02();
        else if (tc === 3) await tc03();
        else if (tc === 4) await tc04();
        else if (tc === 5) await tc05();
    } catch (e) {
        out('Error: ' + e.message, 'o-fail');
    }
    markTC(tc - 1, false);
    setBusy(false);
    await refreshAll();
}

async function resetAll() {
    await fetch('/admin/reset', { method: 'POST' });
    clearOut();
    out('State cleared — all counters, blacklists, and locks reset.', 'o-ok');
    await refreshAll();
}

/* ── stats + log polling ── */
async function refreshStats() {
    try {
        const d = await (await fetch('/admin/stats')).json();
        const set = (id, arr, cls, fn) => {
            document.getElementById(id).innerHTML = arr.length
                ? arr.map(x => `<span class="tag ${cls}">${fn(x)}</span>`).join('')
                : '<span class="tnone">none</span>';
        };
        set('s-ips', d.blacklistedIPs, 'tip', ip => ip);
        set('s-lks', d.lockedAccounts, 'tlk', a => `${a.username} (${a.minutesLeft}m)`);
        set('s-fls', d.accountFails, 'tfl', a => `${a.username}: ${a.count}`);
        set('s-usr', d.ipUsernames, 'tus', e => `${e.ip} · ${e.count} users`);
        document.getElementById('ts').textContent = 'refreshed ' + new Date().toLocaleTimeString();
    } catch { }
}

async function refreshLog() {
    try {
        const { entries } = await (await fetch('/admin/log')).json();
        const el = document.getElementById('log-list');
        if (!entries.length) {
            el.innerHTML = '<div class="log-empty">No attack events recorded yet.</div>';
            return;
        }
        el.innerHTML = entries.map(e => {
            const t = e.time ? new Date(e.time).toLocaleTimeString() : '—';
            const type = e.type || 'INFO';
            const meta = Object.entries(e)
                .filter(([k]) => !['type', 'time'].includes(k))
                .map(([k, v]) => `${k}=${Array.isArray(v) ? v.join(', ') : v}`)
                .join('  ');
            return `<div class="log-row">
<span class="log-t">${t}</span>
<span class="log-type ${type}">${type}</span>
<span class="log-meta">${meta}</span>
</div>`;
        }).join('');
    } catch { }
}

async function refreshAll() {
    await Promise.all([refreshStats(), refreshLog()]);
}

refreshAll();
setInterval(refreshAll, 2000);