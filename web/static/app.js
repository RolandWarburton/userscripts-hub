'use strict';
// The dashboard: the list of scripts beside the open one. The address is the selection:
// / opens nothing, /scripts/<name> opens a script, /new starts one. Every request carries
// X-Requested-With, which the server requires on writes.

const $ = (id) => document.getElementById(id);
const NAME_RE = /^[A-Za-z0-9_-]+$/;
const TEMPLATE = `// ==UserScript==
// @name         New script
// @namespace    userscripts
// @version      1.0.0
// @description
// @match        https://example.com/*
// @grant        none
// ==/UserScript==

(function () {
  'use strict';

})();
`;

// The chosen sort is remembered in this browser; it falls back to name when storage is blocked.
function savedSort() {
  try {
    return localStorage.getItem('sort') === 'modified' ? 'modified' : 'name';
  } catch {
    return 'name';
  }
}

const state = {
  scripts: [], // GET /api/scripts
  site: '', // the domain the list is filtered to, or '' for all scripts
  sort: savedSort(), // 'name' (A–Z) or 'modified' (last edited first)
  open: null, // the open script (GET /api/scripts/<name>), or { isNew: true }
  saved: '', // the editor's text as last loaded or saved, to tell when it has changed
  path: location.pathname,
  escaped: false, // Esc was pressed in the editor: the next Tab leaves it
};

class SignedOut extends Error {}

async function api(path, opts = {}) {
  let res;
  try {
    res = await fetch(path, {
      ...opts,
      credentials: 'same-origin',
      redirect: 'manual', // an ended session redirects to Dex; don't follow it
      headers: { 'X-Requested-With': 'fetch', Accept: 'application/json', ...(opts.headers || {}) },
    });
  } catch {
    throw new Error("Couldn't reach the server. Check your connection and try again.");
  }
  if (res.type === 'opaqueredirect' || res.status === 401) throw new SignedOut();
  const body = await res.json().catch(() => null);
  if (!res.ok) throw new Error((body && body.error) || `The server answered ${res.status}.`);
  return body;
}

// ---- formats ---------------------------------------------------------------

const DAYS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

// Tue 13 Oct 2026, 11:20 am
function when(d) {
  const h = d.getHours() % 12 || 12;
  const m = String(d.getMinutes()).padStart(2, '0');
  return `${DAYS[d.getDay()]} ${d.getDate()} ${MONTHS[d.getMonth()]} ${d.getFullYear()}, ${h}:${m} ${d.getHours() < 12 ? 'am' : 'pm'}`;
}

function ago(d, now = Date.now()) {
  const s = (now - d) / 1000;
  if (s < 60) return 'just now';
  const m = Math.floor(s / 60);
  if (m < 60) return `${m} min ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return h === 1 ? '1 hour ago' : `${h} hours ago`;
  const days = Math.floor(h / 24);
  if (days === 1) return 'yesterday';
  if (days < 7) return `${days} days ago`;
  // older: a short date, the year only when it isn't this one (the full time is the title)
  const year = d.getFullYear() === new Date(now).getFullYear() ? '' : ` ${d.getFullYear()}`;
  return `${d.getDate()} ${MONTHS[d.getMonth()]}${year}`;
}

function size(n) {
  if (n < 1024) return `${n} B`;
  return `${(n / 1024).toFixed(1)} KB`;
}

// A <time> that keeps saying how long ago; refreshed by tick().
function timeEl(iso) {
  const t = document.createElement('time');
  t.dateTime = iso;
  setAgo(t);
  return t;
}

function setAgo(t) {
  const d = new Date(t.dateTime);
  t.textContent = ago(d);
  t.title = when(d);
}

function tick() {
  document.querySelectorAll('time[datetime]').forEach(setAgo);
}

// ---- userscript metadata, as the server reads it -----------------------------

const FIELD_RE = /^\/\/\s*@(\S+)(?:\s+(.*?))?\s*$/;

function parseMeta(src) {
  let inBlock = false;
  const fields = {};
  for (const raw of src.split('\n')) {
    const l = raw.trim();
    if (!inBlock) {
      if (l.startsWith('// ==UserScript==')) inBlock = true;
      continue;
    }
    if (l.startsWith('// ==/UserScript==')) return fields;
    const f = l.match(FIELD_RE);
    if (f && !(f[1] in fields)) fields[f[1]] = f[2] || '';
  }
  return null;
}

// Orders versions the way Tampermonkey (and the server) do: dot-separated parts, the
// number first, and a bare number above the same number with a suffix (1.0 > 1.0b).
function compareVersions(a, b) {
  const pa = a.split('.'), pb = b.split('.');
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const c = comparePart(pa[i] ?? '0', pb[i] ?? '0');
    if (c) return c;
  }
  return 0;
}

function comparePart(x, y) {
  const [, nx, rx] = x.match(/^(\d*)(.*)$/);
  const [, ny, ry] = y.match(/^(\d*)(.*)$/);
  const a = nx.replace(/^0+/, ''), b = ny.replace(/^0+/, '');
  if (a.length !== b.length) return a.length < b.length ? -1 : 1;
  if (a !== b) return a < b ? -1 : 1;
  if (rx === ry) return 0;
  if (rx === '') return 1;
  if (ry === '') return -1;
  return rx < ry ? -1 : 1;
}

// ---- the list --------------------------------------------------------------

async function loadList() {
  try {
    state.scripts = await api('/api/scripts');
    $('list-problem').hidden = true;
  } catch (e) {
    if (e instanceof SignedOut) return signedOut();
    $('list-problem').textContent = `Couldn't load the scripts. ${e.message}`;
    $('list-problem').hidden = false;
  }
  renderList();
}

const ALL_SITES = '*'; // the server's tag for a script that runs on every site
const siteLabel = (d) => (d === ALL_SITES ? 'every site' : d);

// Two-letter country domains whose second level is a public suffix (seek.com.au, seek.co.nz).
const SECOND_LEVEL = new Set(['com', 'co', 'net', 'org', 'gov', 'edu', 'ac', 'id']);

// The site's own name, what a tag's colour is hashed from, so a site's hosts and country
// domains share one: login.microsoftonline.com → microsoftonline, seek.com.au → seek.
function siteName(d) {
  const labels = d.split('.');
  if (labels.length < 2 || /^[\d.]+$/.test(d)) return d;
  const n = labels.length;
  const sld = n >= 3 && labels[n - 1].length === 2 && SECOND_LEVEL.has(labels[n - 2]);
  return labels[n - (sld ? 3 : 2)];
}

// FNV-1a, 32-bit.
function hash(s) {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h;
}

// A tinted tag: its hue comes from the site's name, its lightness from app.css.
function siteTag(d) {
  const tag = document.createElement('span');
  tag.className = 'site-tag';
  tag.textContent = siteLabel(d);
  if (d === ALL_SITES) tag.classList.add('is-all');
  else tag.style.setProperty('--hue', String(hash(siteName(d)) % 360));
  return tag;
}

// The filter offers each domain any script runs on, with how many scripts run there.
function renderSites() {
  const counts = new Map();
  for (const s of state.scripts) for (const d of s.domains || []) counts.set(d, (counts.get(d) || 0) + 1);
  if (state.site && !counts.has(state.site)) state.site = '';
  const domains = [...counts.keys()].sort((a, b) => (a === ALL_SITES) - (b === ALL_SITES) || a.localeCompare(b));
  const all = new Option('All sites', '');
  $('site').replaceChildren(all, ...domains.map((d) => new Option(`${siteLabel(d)} (${counts.get(d)})`, d)));
  $('site').value = state.site;
  $('site-field').hidden = domains.length === 0;
}

function renderList() {
  renderSites();
  const all = state.scripts;
  const list = (state.site ? all.filter((s) => (s.domains || []).includes(state.site)) : [...all]).sort(
    state.sort === 'modified'
      ? (a, b) => (Date.parse(b.modified) || 0) - (Date.parse(a.modified) || 0) || a.name.localeCompare(b.name)
      : (a, b) => a.name.localeCompare(b.name),
  );
  const selected = route().name;
  $('count').textContent = list.length === all.length
    ? `${all.length} ${all.length === 1 ? 'script' : 'scripts'}`
    : `${list.length} of ${all.length} scripts`;
  $('no-scripts').hidden = all.length > 0;
  $('rows').replaceChildren(...list.map((s) => {
    const a = document.createElement('a');
    a.className = 'wc-row' + (s.name === selected ? ' is-selected' : '');
    a.href = `/scripts/${s.name}`;
    a.dataset.nav = '';
    const name = document.createElement('span');
    name.className = 'wc-row-name';
    name.textContent = s.name;
    const when = document.createElement('span');
    when.className = 'wc-ago';
    if (s.modified) when.append(timeEl(s.modified));
    const meta = document.createElement('span');
    meta.className = 'wc-meta';
    for (const text of [s.version ? `v${s.version}` : 'no @version', s.size != null ? size(s.size) : '']) {
      if (!text) continue;
      const span = document.createElement('span');
      span.textContent = text;
      meta.append(span);
    }
    a.append(name, when, meta);
    if (s.domains && s.domains.length) {
      const sites = document.createElement('span');
      sites.className = 'row-sites';
      sites.append(...s.domains.map(siteTag));
      a.append(sites);
    }
    const li = document.createElement('li');
    li.append(a);
    return li;
  }));

  $('total').textContent = String(all.length);
  const latest = all.map((s) => s.modified).filter(Boolean).sort().pop();
  $('last').replaceChildren(latest ? timeEl(latest) : document.createTextNode('none yet'));
}

// ---- routing ---------------------------------------------------------------

function route() {
  const p = location.pathname;
  if (p === '/new') return { kind: 'new' };
  const m = p.match(/^\/scripts\/([A-Za-z0-9_-]+)$/);
  if (m) return { kind: 'script', name: m[1] };
  return { kind: 'none' };
}

function dirty() {
  return state.open !== null && $('source').value !== state.saved;
}

function leaveOK() {
  if (!dirty()) return true;
  const what = state.open.isNew ? 'this new script' : state.open.name;
  return confirm(`Discard your unsaved changes to ${what}?`);
}

function go(path) {
  if (path === location.pathname || !leaveOK()) return;
  history.pushState(null, '', path);
  show();
}

window.addEventListener('popstate', () => {
  if (!leaveOK()) {
    history.pushState(null, '', state.path); // put the address back
    return;
  }
  show();
});

window.addEventListener('beforeunload', (e) => {
  if (dirty()) e.preventDefault();
});

document.addEventListener('click', (e) => {
  const a = e.target.closest('a[data-nav]');
  if (!a || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
  e.preventDefault();
  go(a.getAttribute('href'));
});

async function show() {
  const r = route();
  state.path = location.pathname;
  state.open = null;
  renderList();
  hideConfirm();
  problem('');
  say('');
  $('app').classList.toggle('has-call', r.kind !== 'none');
  $('empty').hidden = r.kind !== 'none';
  $('open').hidden = r.kind === 'none';
  if (r.kind === 'none') {
    document.title = 'userscripts';
    return;
  }
  if (r.kind === 'new') return openNew();

  // Hold the pane empty until the script arrives, so stale text is never editable.
  fill({ title: r.name, facts: false });
  $('editor-card').hidden = true;
  try {
    const info = await api(`/api/scripts/${r.name}`);
    if (route().name === r.name) openScript(info);
  } catch (e) {
    if (e instanceof SignedOut) return signedOut();
    if (route().name !== r.name) return;
    $('editor-card').hidden = false;
    $('source').value = '';
    $('source').disabled = true;
    $('save').disabled = true;
    problem(e.message);
  }
}

function fill({ title, facts, isNew = false }) {
  document.title = `${title} · userscripts`;
  $('title').textContent = title;
  $('facts').hidden = !facts;
  $('hero-ago').hidden = !facts;
  $('name-field').hidden = !isNew;
  $('delete-open').hidden = isNew || !facts;
}

function openScript(info) {
  state.open = info;
  fill({ title: info.name, facts: true });
  $('hero-ago').replaceChildren(timeEl(info.modified));
  $('f-version').textContent = info.version || 'none';
  $('f-modified').textContent = when(new Date(info.modified));
  $('f-size').textContent = size(info.size);
  $('f-name').textContent = (info.metadata && info.metadata.name && info.metadata.name[0]) || 'none';
  $('f-sha').textContent = info.sha256;
  $('f-install').href = info.install_url;
  $('f-install').textContent = info.install_url;
  $('copy').textContent = 'Copy';
  setEditor(info.source);
}

function openNew() {
  state.open = { isNew: true };
  fill({ title: 'New script', facts: false, isNew: true });
  $('name').value = '';
  checkName();
  setEditor(TEMPLATE);
  $('name').focus();
}

function setEditor(text) {
  $('editor-card').hidden = false;
  $('source').disabled = false;
  $('save').disabled = false;
  $('source').value = text;
  state.saved = text;
}

// ---- messages --------------------------------------------------------------

let sayTimer;

// say shows one word of feedback that fades after two seconds.
function say(text) {
  clearTimeout(sayTimer);
  $('status').textContent = text;
  if (text) sayTimer = setTimeout(() => { $('status').textContent = ''; }, 2000);
}

function problem(text) {
  $('problem').textContent = text;
  $('problem').hidden = !text;
}

function signedOut() {
  $('sign-in').href = location.pathname;
  $('ended').hidden = false;
}

// ---- new script name -------------------------------------------------------

function nameProblem(name) {
  if (!name) return 'Give the script a name.';
  if (!NAME_RE.test(name)) return 'Use only letters, digits, _ and -.';
  if (state.scripts.some((s) => s.name === name)) return `There is already a script called ${name}. Open it from the list to change it.`;
  return '';
}

function checkName() {
  const name = $('name').value.trim();
  const bad = name ? nameProblem(name) : '';
  $('name-hint').textContent = bad ||
    `Letters, digits, _ and - only. It becomes the file name: ${name || 'my-script'}.user.js.`;
  $('name-hint').classList.toggle('is-bad', !!bad);
}

$('name').addEventListener('input', checkName);

// ---- save ------------------------------------------------------------------

async function save() {
  if (!state.open) return;
  const src = $('source').value;
  const isNew = !!state.open.isNew;
  const name = isNew ? $('name').value.trim() : state.open.name;
  const meta = parseMeta(src);

  let bad = isNew ? nameProblem(name) : '';
  if (!bad && !meta) bad = 'The source needs a // ==UserScript== … // ==/UserScript== block.';
  if (!bad && !meta.name) bad = 'The metadata block needs an @name.';
  if (!bad && !meta.version) bad = 'The metadata block needs an @version.';
  if (!bad && !isNew && compareVersions(meta.version, state.open.version || '') <= 0) {
    bad = `@version ${meta.version} isn't higher than the stored ${state.open.version}. ` +
      'Raise it before saving.';
  }
  if (bad) {
    problem(bad);
    say('');
    return;
  }

  problem('');
  $('save').disabled = true;
  $('save').textContent = 'Saving…';
  try {
    await api(`/api/scripts/${name}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'text/plain; charset=utf-8' },
      body: src,
    });
    // The server stores the source without @updateURL/@downloadURL; show what it kept.
    const info = await api(`/api/scripts/${name}`);
    state.saved = $('source').value; // nothing to discard while the address changes
    if (isNew) history.replaceState(null, '', `/scripts/${name}`);
    state.path = location.pathname;
    openScript(info);
    await loadList();
    say('Saved');
  } catch (e) {
    if (e instanceof SignedOut) return signedOut();
    problem(e.message);
  } finally {
    $('save').disabled = false;
    $('save').textContent = 'Save';
  }
}

$('save').addEventListener('click', save);

$('sort').value = state.sort;
$('sort').addEventListener('change', () => {
  state.sort = $('sort').value;
  try {
    localStorage.setItem('sort', state.sort);
  } catch {}
  renderList();
});

$('site').addEventListener('change', () => {
  state.site = $('site').value;
  renderList();
});

document.addEventListener('keydown', (e) => {
  if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 's' && !$('open').hidden) {
    e.preventDefault();
    save();
  }
});

// ---- delete ----------------------------------------------------------------

function hideConfirm() {
  $('confirm').hidden = true;
  $('delete-open').hidden = !state.open || !!state.open.isNew;
}

$('delete-open').addEventListener('click', () => {
  $('confirm-text').textContent = `Delete ${state.open.name} from the server? ` +
    'Installed copies keep running but stop getting updates. This cannot be undone.';
  $('confirm').hidden = false;
  $('delete-open').hidden = true;
  $('delete-cancel').focus();
});

$('delete-cancel').addEventListener('click', () => {
  hideConfirm();
  $('delete-open').focus();
});

$('delete').addEventListener('click', async () => {
  const name = state.open.name;
  $('delete').disabled = true;
  try {
    await api(`/api/scripts/${name}`, { method: 'DELETE' });
    state.saved = $('source').value; // deleted: nothing left to keep
    await loadList();
    go('/');
  } catch (e) {
    if (e instanceof SignedOut) return signedOut();
    hideConfirm();
    problem(`Couldn't delete ${name}. ${e.message}`);
  } finally {
    $('delete').disabled = false;
  }
});

// ---- copy ------------------------------------------------------------------

let copyTimer;
$('copy').addEventListener('click', async () => {
  clearTimeout(copyTimer);
  try {
    await navigator.clipboard.writeText($('f-install').href);
    $('copy').textContent = 'Copied';
  } catch {
    $('copy').textContent = 'Copy failed';
  }
  copyTimer = setTimeout(() => { $('copy').textContent = 'Copy'; }, 2000);
});

// ---- keyboard: Escape closes, Tab indents in the editor -------------------------

document.addEventListener('keydown', (e) => {
  if (e.key !== 'Escape' || e.defaultPrevented) return;
  const tag = document.activeElement && document.activeElement.tagName;
  if (tag === 'TEXTAREA' || tag === 'INPUT') return;
  if (!$('confirm').hidden) {
    hideConfirm();
    return;
  }
  if (route().kind !== 'none') go('/');
});

// The indent the script already uses: a tab, or the commonest step between lines' spaces.
function indentUnit(src) {
  let tabs = 0, prev = 0;
  const steps = { 2: 0, 4: 0 };
  for (const line of src.split('\n')) {
    if (!line.trim()) continue;
    const lead = line.match(/^[\t ]*/)[0];
    if (lead.startsWith('\t')) {
      tabs++;
      continue;
    }
    const d = Math.abs(lead.length - prev);
    if (d in steps) steps[d]++;
    prev = lead.length;
  }
  if (tabs > steps[2] + steps[4]) return '\t';
  return steps[4] > steps[2] ? '    ' : '  ';
}

// replace swaps the text between start and end, through the browser's editing so undo works.
function replace(ta, start, end, text) {
  ta.setSelectionRange(start, end);
  if (!document.execCommand('insertText', false, text)) ta.setRangeText(text, start, end, 'end');
}

function outdentLine(line, unit) {
  if (line.startsWith(unit)) return line.slice(unit.length);
  if (line.startsWith('\t')) return line.slice(1);
  return line.replace(new RegExp(`^ {1,${unit === '\t' ? 4 : unit.length}}`), '');
}

$('source').addEventListener('keydown', (e) => {
  const ta = e.currentTarget;
  if (e.key === 'Escape') {
    state.escaped = true;
    return;
  }
  if (e.key !== 'Tab' || e.ctrlKey || e.metaKey || e.altKey) {
    if (e.key !== 'Shift') state.escaped = false;
    return;
  }
  if (state.escaped) {
    state.escaped = false;
    return; // let the browser move focus on
  }
  e.preventDefault();
  const unit = indentUnit(ta.value);
  const { selectionStart: s, selectionEnd: end, value } = ta;
  const multi = value.slice(s, end).includes('\n');
  if (!e.shiftKey && !multi) {
    replace(ta, s, end, unit);
    return;
  }
  // Indent or outdent every line the selection touches.
  const from = value.lastIndexOf('\n', s - 1) + 1;
  let to = end;
  if (to > s && value[to - 1] === '\n') to--; // a selection ending at a line start leaves that line alone
  const nl = value.indexOf('\n', to);
  to = nl === -1 ? value.length : nl;
  const lines = value.slice(from, to).split('\n');
  const changed = lines.map((l) => (e.shiftKey ? outdentLine(l, unit) : (l ? unit + l : l))).join('\n');
  if (changed === value.slice(from, to)) return;
  replace(ta, from, to, changed);
  ta.setSelectionRange(from, from + changed.length);
});

// ---- start -----------------------------------------------------------------

async function start() {
  try {
    const me = await api('/api/me');
    $('email').textContent = me.email;
  } catch (e) {
    if (e instanceof SignedOut) return signedOut();
  }
  await loadList();
  await show();
  setInterval(tick, 15000);
}

start();
