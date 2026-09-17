/* Run: node scripts/test_site_docs.js. No browser or external packages required. */
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const root = path.resolve(__dirname, '..');
const source = fs.readFileSync(path.join(root, 'site/js/docs.js'), 'utf8');
const decode = s => s.replace(/&(?:amp|lt|gt|quot|apos|nbsp);/g, x => ({
  '&amp;': '&', '&lt;': '<', '&gt;': '>', '&quot;': '"', '&apos;': "'", '&nbsp;': '\u00a0'
})[x]);

// Minimal DOM surface used by the helper; tests exercise its actual event handlers.
class Node {
  constructor(tag, value = '', classes = '') {
    this.tag = tag; this.value = value; this.classes = classes; this.children = [];
    this.nodeType = tag === '#text' ? 3 : 1;
  }
  append(node) { node.parent = this; this.children.push(node); }
  get nextSibling() {
    return this.parent?.children[this.parent.children.indexOf(this) + 1];
  }
  get textContent() { return this.nodeType === 3 ? this.value : this.children.map(n => n.textContent).join(''); }
  set textContent(value) { this.value = value; this.children = []; }
  cloneNode() {
    const node = new Node(this.tag, this.value, this.classes);
    this.children.forEach(child => node.append(child.cloneNode()));
    return node;
  }
  querySelectorAll(selector) {
    assert.equal(selector, 'span.c-grn');
    return this.children.flatMap(n => [
      ...(n.tag === 'span' && n.classes.split(' ').includes('c-grn') ? [n] : []),
      ...n.querySelectorAll(selector)
    ]);
  }
  remove() { this.parent.children.splice(this.parent.children.indexOf(this), 1); }
}
function preNode(html) {
  const pre = new Node('pre'), stack = [pre];
  for (const token of html.match(/<[^>]*>|[^<]+/g) || []) {
    if (token.startsWith('</')) stack.pop();
    else if (token.startsWith('<')) {
      const tag = /^<(\w+)/.exec(token)[1];
      const node = new Node(tag, '', /class="([^"]*)"/.exec(token)?.[1] || '');
      stack.at(-1).append(node);
      if (tag !== 'br') stack.push(node);
    } else stack.at(-1).append(new Node('#text', decode(token)));
  }
  return pre;
}
function run(html, locale = 'ru', cards = []) {
  let onCopy, onSearch, copied;
  const pre = preNode(html);
  const bar = {querySelector: () => null, appendChild: () => {}};
  const block = {querySelector: s => s === 'pre' ? pre : bar};
  const input = {value: '', addEventListener: (_, fn) => { onSearch = fn; }};
  const count = {};
  const document = {
    readyState: 'complete', documentElement: {lang: locale},
    createElement: () => ({addEventListener: (_, fn) => { onCopy = fn; }}),
    getElementById: id => id === 'docSearch' ? input : count,
    querySelectorAll: s => s === '.code' ? [block] : s === '.doc-card[data-search]' ? cards : []
  };
  vm.runInNewContext(source, {
    document, navigator: {clipboard: {writeText: text => { copied = text; return Promise.resolve(); }}},
    window: {setTimeout: () => {}}, MutationObserver: class { observe() {} }
  });
  onCopy();
  return {copied, search(q) { input.value = q; onSearch(); return cards.filter(c => !c.hidden); }, count};
}

for (const [html, expected] of [
  ['<span class="c-grn">$</span> sudo systemctl status qeli-server', 'sudo systemctl status qeli-server\n'],
  ['<span class="c-grn">PS&gt;</span> Get-FileHash "$env:TEMP\\qeli.exe"', 'Get-FileHash "$env:TEMP\\qeli.exe"\n'],
  ['<span class="c-grn">$</span> echo "$HOME"\n<span class="c-grn">$</span> ip -6 route', 'echo "$HOME"\nip -6 route\n'],
  ['[user:alice]\npassword_hash = $argon2id$v=19\nstatic_ipv6 = 2001:db8::100', '[user:alice]\npassword_hash = $argon2id$v=19\nstatic_ipv6 = 2001:db8::100\n'],
  ['<span class="c-grn">$env:TEMP</span>\n$ literal\nPS&gt; literal', '$env:TEMP\n$ literal\nPS> literal\n'],
  ['# Comment\n<span class="c-grn">$</span> echo one \\\n  two\n\n<span class="c-grn">$</span> echo "&lt;ok&gt;"', '# Comment\necho one \\\n  two\n\necho "<ok>"\n']
]) assert.equal(run(html).copied, expected);

for (const locale of ['ru', 'en']) {
  const base = locale === 'en' ? 'site/en' : 'site';
  const hub = fs.readFileSync(path.join(root, base, 'docs/index.html'), 'utf8');
  const cards = [...hub.matchAll(/<a class="doc-card[^>]*href="([^"]*)"[^>]*data-search="([^"]*)"[^>]*>([\s\S]*?)<\/a>/g)].map(m => ({
    href: m[1], getAttribute: () => m[2], textContent: preNode(m[3]).textContent
  }));
  assert.equal(cards.length, [...hub.matchAll(/data-search=/g)].length);
  assert(cards.length > 0);
  const ui = run('', locale, cards);
  for (const q of ['ndp', 'NDP proxy', 'ndp_proxy', 'routing.ipv6.ndp_proxy_interface', 'static_ipv6']) {
    assert(ui.search(q).some(c => c.href.endsWith('/docs/ipv6/')), locale + ': ' + q);
  }
  assert.equal(ui.search('no_such_qeli_parameter').length, 0);
  assert.equal(ui.search('').length, cards.length);
  const install = fs.readFileSync(path.join(root, base, 'install/debian/index.html'), 'utf8');
  const html = /<pre><code>([\s\S]*?)<\/code><\/pre>/.exec(install)[1];
  assert(run(html, locale).copied.startsWith('curl -fsSLO '));
  assert(!/^\$ /m.test(run(html, locale).copied));
}
console.log('PASS: clipboard preservation, actual Debian commands, RU/EN NDP search and reset');
