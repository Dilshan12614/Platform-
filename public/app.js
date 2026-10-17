const $ = id => document.getElementById(id);
let currentUser = null;
let poller = null;
async function api(url, options = {}) {
  const res = await fetch(url, { credentials: 'same-origin', headers: { 'Content-Type': 'application/json', ...(options.headers || {}) }, ...options });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
  return data;
}
function show(el, yes = true) { el.classList.toggle('hidden', !yes); }
function message(id, text, isError = false) { const el = $(id); el.textContent = text; el.classList.toggle('error', isError); show(el, true); }
function setView(user) {
  currentUser = user;
  show($('loginView'), !user); show($('appView'), !!user); show($('userArea'), !!user);
  if (user) { $('userEmail').textContent = `${user.email}${user.role === 'admin' ? ' · ADMIN' : ''}`; show($('adminCard'), user.role === 'admin'); refresh(); if (poller) clearInterval(poller); poller = setInterval(refresh, 5000); }
  else { if (poller) clearInterval(poller); poller = null; }
}
function fmtUptime(n) { n = Number(n || 0); const d=Math.floor(n/86400),h=Math.floor(n%86400/3600),m=Math.floor(n%3600/60),s=n%60; return `${d}d ${h}h ${m}m ${s}s`; }
async function refresh() {
  if (!currentUser) return;
  try {
    const d = await api('/api/dashboard'); const b = d.bot || {};
    const status = b.status || 'disconnected'; const pill = $('statusPill');
    pill.innerHTML = `<span class="dot ${status === 'connected' ? 'green' : status === 'disconnected' ? 'red' : ''}"></span><span>${status}</span>`;
    $('phone').textContent = b.phone_number || 'Not paired'; $('uptime').textContent = d.workerRunning ? fmtUptime(d.workerUptimeSeconds) : 'Worker stopped'; $('updated').textContent = b.updated_at || '—';
    if (b.last_error) { $('botError').textContent = b.last_error; show($('botError')); } else show($('botError'), false);
    $('disconnect').disabled = !d.workerRunning && status === 'disconnected';
    renderPlugins(d.plugins || []);
  } catch (e) { if (e.message.toLowerCase().includes('sign in')) setView(null); }
  if (currentUser?.role === 'admin') loadUsers();
}
function renderPlugins(plugins) {
  $('plugins').innerHTML = '';
  for (const p of plugins) {
    const row = document.createElement('div'); row.className = 'plugin';
    const info = document.createElement('div'); const name = document.createElement('strong'); name.textContent = p.name;
    const desc = document.createElement('small'); desc.textContent = p.description; info.append(name, document.createElement('br'), desc);
    const btn = document.createElement('button'); btn.className = `switch ${p.enabled ? 'on' : ''}`; btn.textContent = p.enabled ? 'Enabled' : 'Disabled'; btn.setAttribute('aria-pressed', String(p.enabled)); btn.onclick = async () => { btn.disabled = true; try { await api(`/api/plugins/${encodeURIComponent(p.id)}/toggle`, { method: 'POST', body: '{}' }); await refresh(); } catch(e) { alert(e.message); } finally { btn.disabled = false; } };
    row.append(info, btn); $('plugins').append(row);
  }
}
async function loadUsers() {
  try { const data = await api('/api/admin/users'); const box = $('usersList'); box.innerHTML = '<h3 style="font-size:14px;margin-top:22px">Recent users</h3>'; for (const u of data.users) { const row = document.createElement('div'); row.className = 'statrow'; const a = document.createElement('span'); a.textContent = u.email; const b = document.createElement('span'); b.className = 'muted'; b.textContent = `${u.role} · ${u.status || 'disconnected'}`; row.append(a,b); box.append(row); } } catch {}
}
$('loginForm').addEventListener('submit', async e => { e.preventDefault(); try { const d = await api('/api/auth/login', { method: 'POST', body: JSON.stringify({ email: $('email').value, password: $('password').value }) }); show($('loginMsg'), false); setView(d.user); } catch(err) { message('loginMsg', err.message, true); } });
$('logout').onclick = async () => { try { await api('/api/auth/logout', { method: 'POST', body: '{}' }); } catch {} setView(null); };
$('pairForm').addEventListener('submit', async e => { e.preventDefault(); const btn = e.submitter; btn.disabled = true; $('pairCode').textContent = ''; show($('pairCode'), false); show($('pairMsg'), false); try { const d = await api('/api/pair', { method: 'POST', body: JSON.stringify({ phone: $('phoneInput').value }) }); $('pairCode').textContent = d.code; show($('pairCode')); message('pairMsg', d.message); await refresh(); } catch(err) { message('pairMsg', err.message, true); } finally { btn.disabled = false; } });
$('disconnect').onclick = async () => { if (!confirm('Stop this WhatsApp worker? Saved session credentials will remain on the server.')) return; try { await api('/api/disconnect', { method: 'POST', body: '{}' }); await refresh(); } catch(e) { alert(e.message); } };
$('userForm').addEventListener('submit', async e => { e.preventDefault(); try { await api('/api/admin/users', { method: 'POST', body: JSON.stringify({ email: $('newEmail').value, password: $('newPassword').value }) }); message('adminMsg', 'User created successfully.'); $('userForm').reset(); await loadUsers(); } catch(err) { message('adminMsg', err.message, true); } });
(async () => { try { const d = await api('/api/me'); setView(d.user); } catch { setView(null); } })();
