'use strict';
'require view';
'require form';
'require uci';
'require rpc';
'require poll';
'require ui';

// procd/ubus: is the qeli service instance running?
var callServiceList = rpc.declare({
	object: 'service',
	method: 'list',
	params: [ 'name' ],
	expect: { '': {} }
});

// LuCI init-action helper (granted in the ACL): start/stop/restart/enable/disable.
var callInitAction = rpc.declare({
	object: 'luci',
	method: 'setInitAction',
	params: [ 'name', 'action' ],
	expect: { result: false }
});

function getRunning() {
	return L.resolveDefault(callServiceList('qeli'), {}).then(function (res) {
		try {
			var inst = res['qeli']['instances'];
			for (var k in inst) if (inst[k].running) return true;
		} catch (e) {}
		return false;
	});
}

function svc(action) {
	return callInitAction('qeli', action).then(function () {
		ui.addNotification(null, E('p', _('qeli: %s requested').format(action)), 'info');
	});
}

// Autostart intent, as the init script actually reads it. `start_service` refuses to run
// unless `qeli.main.enabled` is 1, so the rc.d symlink alone decides nothing here — the
// UCI flag is the real switch, and the status line has to show it or a "stopped" tunnel
// that will silently come back on the next boot looks identical to one that will not. (C-21)
function getEnabled() {
	return uci.load('qeli').then(function () {
		return uci.get('qeli', 'main', 'enabled') == '1';
	}).catch(function () { return false; });
}

function statusText(running, enabled) {
	if (running) return _('● connected / running');
	return enabled ? _('○ stopped (autostart ON — starts again on boot)') : _('○ stopped');
}

return view.extend({
	load: function () {
		return Promise.all([ getRunning(), getEnabled() ]);
	},

	render: function (data) {
		var running = data[0];
		var enabled = data[1];
		var m, s, o;

		m = new form.Map('qeli', _('qeli VPN client'),
			_('Dial out to a qeli server (REALITY / anti-DPI, post-quantum). ' +
			  'Enable <em>Route the whole LAN</em> to use the router as a full-tunnel gateway. ' +
			  'Get the connection from the server\'s <code>qeli://</code> link and the key from ' +
			  '<code>qeli show-identity</code>.'));

		// ── Status / control ──
		s = m.section(form.TypedSection, '_status');
		s.anonymous = true;
		s.render = function () {
			var view = E('div', { class: 'cbi-section' }, [
				E('h3', _('Status')),
				E('p', {}, [
					E('span', { style: 'font-weight:bold' },
						E('span', { style: 'color:' + (running ? '#2e7d32' : '#b71c1c') },
							statusText(running, enabled))),
				]),
				E('div', { class: 'cbi-section-actions' }, [
					// Connect must set the UCI flag too: `start_service` returns immediately
					// when `qeli.main.enabled` is 0, so enable+start alone did nothing at all
					// and the button appeared broken. (C-21)
					E('button', { class: 'btn cbi-button-positive',
						click: ui.createHandlerFn(this, function () {
							uci.set('qeli', 'main', 'enabled', '1');
							return uci.save()
								.then(function () { return svc('enable'); })
								.then(function () { return svc('start'); })
								.then(L.bind(L.ui.changes.apply, L.ui.changes));
						}) }, _('Connect')),
					' ',
					// Disconnect clears the autostart intent as well. `stop` alone left
					// `enabled=1` and the rc.d symlink in place, so the tunnel returned on the
					// next boot while the UI had shown it as disconnected. (C-21)
					E('button', { class: 'btn cbi-button-negative',
						click: ui.createHandlerFn(this, function () {
							uci.set('qeli', 'main', 'enabled', '0');
							return uci.save()
								.then(function () { return svc('stop'); })
								.then(function () { return svc('disable'); })
								.then(L.bind(L.ui.changes.apply, L.ui.changes));
						}) }, _('Disconnect')),
					' ',
					E('button', { class: 'btn',
						click: ui.createHandlerFn(this, function () { return svc('restart'); }) }, _('Restart')),
				])
			]);
			// live status refresh
			poll.add(function () {
				// Poll both: a tunnel can be stopped-but-enabled, and that difference is
				// exactly what the old single-value status hid. (C-21)
				return Promise.all([ getRunning(), getEnabled() ]).then(function (v) {
					var dot = view.querySelector('span span');
					if (!dot) return;
					dot.textContent = statusText(v[0], v[1]);
					dot.style.color = v[0] ? '#2e7d32' : '#b71c1c';
				});
			}, 5);
			return view;
		};

		// ── Connection ──
		s = m.section(form.NamedSection, 'main', 'qeli', _('Connection'));
		s.addremove = false;

		o = s.option(form.Flag, 'enabled', _('Enabled'), _('Start the tunnel on boot.'));
		o.rmempty = false;

		o = s.option(form.Value, 'server', _('Server'), _('host:port of the qeli server.'));
		o.placeholder = 'vpn.example.com:443';
		o.rmempty = false;

		o = s.option(form.ListValue, 'proto', _('Transport'));
		o.value('tcp', 'TCP');
		o.value('udp', 'UDP');
		o.default = 'tcp';

		o = s.option(form.Value, 'user', _('Username'));
		o = s.option(form.Value, 'pass', _('Password'));
		o.password = true;

		o = s.option(form.Value, 'key', _('Server key'),
			_('Server identity public key (hex) for pinning — <code>qeli show-identity</code>. ' +
			  'Empty / all-zero = TOFU (trust on first use).'));
		o.datatype = 'and(hexstring,maxlength(64))';

		o = s.option(form.Flag, 'bind_static', _('Bind to server identity (H-1)'),
			_('On by default; <strong>requires a real pinned key</strong>. Turn off only with a zero/TOFU key.'));
		o.default = '1';

		// ── Obfuscation ──
		s = m.section(form.NamedSection, 'main', 'qeli', _('Obfuscation'));
		s.addremove = false;

		o = s.option(form.ListValue, 'mode', _('Wire mode'),
			_('Must match the server. On low-end MIPS prefer fake-tls / obfs / plain; ' +
			  'reality-tls is heavy (double AEAD) — ARM only.'));
		o.value('fake-tls', 'fake-tls');
		o.value('reality-tls', 'reality-tls (REALITY)');
		o.value('obfs', 'obfs');
		o.value('plain', 'plain');
		o.default = 'fake-tls';

		o = s.option(form.Value, 'sni', _('SNI'), _('Front domain for fake-tls / reality-tls.'));
		o.depends('mode', 'fake-tls');
		o.depends('mode', 'reality-tls');
		o.placeholder = 'www.cloudflare.com';

		o = s.option(form.Value, 'reality_sid', _('REALITY short_id'));
		o.depends('mode', 'reality-tls');

		o = s.option(form.Value, 'obfs_key', _('obfs key'), _('Shared secret — required for obfs.'));
		o.depends('mode', 'obfs');
		o.password = true;

		o = s.option(form.ListValue, 'front', _('obfs fronting'));
		o.value('websocket', 'websocket (default)');
		o.value('none', 'none');
		o.depends('mode', 'obfs');

		o = s.option(form.Flag, 'quic', _('QUIC'), _('udp+quic profiles.'));
		o.depends('proto', 'udp');

		// ── Routing / DNS ──
		s = m.section(form.NamedSection, 'main', 'qeli', _('Routing & DNS'));
		s.addremove = false;

		o = s.option(form.Flag, 'gateway', _('Route the whole LAN (full-tunnel)'),
			_('Send all router/LAN traffic through the tunnel. Off = split-tunnel ' +
			  '(only the tunnel subnet + pushed routes). The firewall zone <code>qeli</code> NATs it out.'));

		o = s.option(form.Value, 'dns', _('DNS'),
			_('<code>off</code> = leave the router resolver alone (recommended); ' +
			  '<code>tunnel</code> = use the server\'s; or a comma list of resolvers.'));
		o.default = 'off';

		o = s.option(form.Value, 'dev', _('TUN device'));
		o.default = 'qeli0';
		o.datatype = 'maxlength(15)';

		o = s.option(form.Value, 'mtu', _('MTU'), _('0 = auto (server-pushed).'));
		o.datatype = 'range(0,9000)';

		o = s.option(form.Flag, 'kill_switch', _('Kill-switch'),
			_('Client-side firewall lock: block all egress except the tunnel while connected.'));

		o = s.option(form.ListValue, 'log_level', _('Log level'));
		o.value('error'); o.value('warn'); o.value('info'); o.value('debug');
		o.default = 'info';

		o = s.option(form.ListValue, 'log_time_format', _('Log timestamp'),
			_('Timestamp the client puts in front of each line. Leave at "none" — syslog stamps every line already, so anything else is a second timestamp in logread.'));
		o.value('none', _('none — syslog stamps it'));
		o.value('datetime', _('2026-07-18 18:10:03.259 (local)'));
		o.value('rfc3339', _('2026-07-18T18:10:03.259Z (UTC)'));
		o.value('time', _('18:10:03.259 (no date)'));
		o.value('epoch', _('1782000603.259 (unix)'));
		o.default = 'none';

		return m.render();
	}
});
