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

return view.extend({
	load: function () {
		return Promise.all([ getRunning() ]);
	},

	render: function (data) {
		var running = data[0];
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
					E('span', { style: 'font-weight:bold' }, running
						? E('span', { style: 'color:#2e7d32' }, _('● connected / running'))
						: E('span', { style: 'color:#b71c1c' }, _('○ stopped'))),
				]),
				E('div', { class: 'cbi-section-actions' }, [
					E('button', { class: 'btn cbi-button-positive',
						click: ui.createHandlerFn(this, function () { return svc('enable').then(function(){ return svc('start'); }).then(L.bind(L.ui.changes.apply, L.ui.changes)); }) }, _('Connect')),
					' ',
					E('button', { class: 'btn cbi-button-negative',
						click: ui.createHandlerFn(this, function () { return svc('stop'); }) }, _('Disconnect')),
					' ',
					E('button', { class: 'btn',
						click: ui.createHandlerFn(this, function () { return svc('restart'); }) }, _('Restart')),
				])
			]);
			// live status refresh
			poll.add(function () {
				return getRunning().then(function (r) {
					var dot = view.querySelector('span span');
					if (!dot) return;
					dot.textContent = r ? _('● connected / running') : _('○ stopped');
					dot.style.color = r ? '#2e7d32' : '#b71c1c';
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

		return m.render();
	}
});
