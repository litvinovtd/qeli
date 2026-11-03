#!/usr/bin/env ucode

'use strict';

import * as fs from 'fs';

const RUNDIR = '/var/run/qeli';
const secretPaths = {
	pass: RUNDIR + '/password',
	obfs_key: RUNDIR + '/obfs-key',
};

const actions = {
	start: true,
	stop: true,
	restart: true,
	enable: true,
	disable: true,
};

function secretPath(name) {
	return secretPaths[name];
}

function validSecret(value) {
	if (type(value) != 'string' || length(value) == 0 || length(value) > 4096)
		return false;

	// ucode uses POSIX regexes; check the exact C0/DEL bytes without JS escapes.
	for (let i = 0; i < length(value); i++) {
		const byte = ord(value, i);
		if (byte < 32 || byte == 127)
			return false;
	}
	return true;
}

function writeSecret(name, value) {
	if (!secretPath(name) || !validSecret(value))
		exit(UBUS_STATUS_INVALID_ARGUMENT);

	// OpenWrt 24.10/25.12 fs.popen() requires a command string. Both commands are
	// literals: caller-controlled names/values never become shell text or argv.
	// The init script owns validation and atomic mktemp/rename; value uses stdin.
	const command = name == 'pass'
		? '/etc/init.d/qeli set_secret pass'
		: '/etc/init.d/qeli set_secret obfs_key';
	const input = value + '\n';
	const process = fs.popen(command, 'we');
	if (!process)
		exit(UBUS_STATUS_UNKNOWN_ERROR);
	const written = process.write(input);
	const code = process.close();
	if (written !== length(input) || code !== 0)
		exit(UBUS_STATUS_UNKNOWN_ERROR);
}

function secretExists(path) {
	const directory = fs.lstat(RUNDIR);
	if (!directory || directory.type != 'directory')
		return false;
	const entry = fs.lstat(path);
	return !!entry && entry.type == 'file' && entry.size > 0 && entry.size <= 4096 &&
		fs.access(path, 'r') === true;
}

const methods = {
	service_status: {
		call: function() {
			const code = system('/etc/init.d/qeli status_enabled >/dev/null 2>&1');
			return { enabled: code === 0 ? true : (code === 1 ? false : null) };
		}
	},

	service_action: {
		args: { action: '' },
		call: function(request) {
			const action = request.args.action;
			if (!actions[action])
				exit(UBUS_STATUS_INVALID_ARGUMENT);

			// The action comes from the closed whitelist above. No caller-controlled text is
			// ever interpreted as a shell fragment beyond one of the five fixed init verbs.
			const code = system(`/etc/init.d/qeli ${action} >/dev/null 2>&1`);
			return { result: code == 0, code };
		}
	},

	secret_status: {
		call: function() {
			return {
				pass: secretExists(secretPaths.pass),
				obfs_key: secretExists(secretPaths.obfs_key),
			};
		}
	},

	set_secret: {
		args: { name: '', value: '' },
		call: function(request) {
			writeSecret(request.args.name, request.args.value);
			return { result: true };
		}
	},

	clear_secret: {
		args: { name: '' },
		call: function(request) {
			const name = request.args.name;
			if (name != 'pass' && name != 'obfs_key')
				exit(UBUS_STATUS_INVALID_ARGUMENT);
			// The init script owns secret deletion and propagates filesystem errors.
			// Only the two literal names above can enter this fixed command.
			const code = system(`/etc/init.d/qeli clear_secrets ${name} >/dev/null 2>&1`);
			return { result: code === 0, code };
		}
	}
};

return { 'luci.qeli': methods };
