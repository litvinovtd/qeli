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
	return type(value) == 'string' && length(value) > 0 && length(value) <= 4096 &&
		!match(value, /[\x00-\x1f\x7f]/);
}

function writeSecret(name, value) {
	if (!secretPath(name) || !validSecret(value))
		exit(UBUS_STATUS_INVALID_ARGUMENT);

	// Delegate to the init script through stdin. The array form bypasses the shell,
	// the secret never enters argv, and the init script owns validation + atomic mktemp/rename.
	const input = value + '\n';
	const process = fs.popen(['/etc/init.d/qeli', 'set_secret', name], 'we');
	if (!process)
		exit(UBUS_STATUS_UNKNOWN_ERROR);
	const written = process.write(input);
	const code = process.close();
	if (written != length(input) || code != 0)
		exit(UBUS_STATUS_UNKNOWN_ERROR);
}

const methods = {
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
				pass: fs.access(secretPaths.pass, 'r') == true,
				obfs_key: fs.access(secretPaths.obfs_key, 'r') == true,
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
			const path = secretPath(request.args.name);
			if (!path)
				exit(UBUS_STATUS_INVALID_ARGUMENT);
			fs.unlink(path);
			return { result: true };
		}
	}
};

return { 'luci.qeli': methods };
