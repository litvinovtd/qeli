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

// Read procd independently of the tunnel report. This fixed, one-second query
// cannot select arbitrary services or expose the environment returned by procd.
function processStatus() {
    try {
        const child = fs.popen('ubus -t 1 call service list \'{"name":"qeli"}\'', 'r');
        if (!child)
            return null;
        const text = child.read(65536);
        const code = child.close();
        if (code !== 0 || type(text) != 'string' || length(text) >= 65536)
            return null;
        const instance = json(text)?.qeli?.instances?.qeli;
        return instance && instance.running === true
            ? { running: true, pid: instance.pid }
            : { running: false };
    } catch (e) {
        return null;
    }
}

function tunnelStatus(process) {
    const unavailable = { available: false };
    try {
        if (!process || process.running !== true || type(process.pid) != 'int' || process.pid <= 0)
            return unavailable;
        const directory = fs.lstat(RUNDIR);
        const entry = fs.lstat(RUNDIR + '/status.json');
        if (directory?.type != 'directory' || directory.uid !== 0 || (directory.mode & 18) || entry?.type != 'file' || entry.size <= 0 || entry.size > 8192)
            return unavailable;
        const report = json(fs.readfile(RUNDIR + '/status.json'));
        const runtime = report?.runtime;
        const tunnel = report?.tunnel;
        const boot = trim(fs.readfile('/proc/sys/kernel/random/boot_id') || '');
        const stat = fs.readfile(`/proc/${process.pid}/stat`) || '';
        const fields = split(trim(substr(stat, rindex(stat, ')') + 1)), /[[:space:]]+/);
        const uptime = split(fs.readfile('/proc/uptime') || '', ' ');
        const now = +uptime[0] * 1000;
        if (report?.schema !== 1 || !runtime || !tunnel || !boot ||
            runtime.pid !== process.pid || runtime.boot_id !== boot ||
            type(runtime.start_ticks) != 'string' || runtime.start_ticks !== fields[19] ||
            fields[0] == 'Z' || fields[0] == 'X' ||
            runtime.run_id !== `${boot}:${process.pid}:${fields[19]}` ||
            type(runtime.updated_boottime_ms) != 'int' || !now ||
            runtime.updated_boottime_ms > now + 100 || now - runtime.updated_boottime_ms > 10000 ||
            type(tunnel.device) != 'string' || !match(tunnel.device, /^qeli[A-Za-z0-9._-]*$/) || length(tunnel.device) > 15 ||
            index(['connecting', 'connected', 'reconnecting', 'stopped', 'error'], tunnel.state) < 0)
            return unavailable;
        // Re-read identity after the report: a concurrent procd respawn must not
        // make a predecessor's Connected record valid for the successor.
        const again = fs.readfile(`/proc/${process.pid}/stat`) || '';
        const identity = split(trim(substr(again, rindex(again, ')') + 1)), /[[:space:]]+/);
        if (identity[19] !== fields[19] || identity[0] == 'Z' || identity[0] == 'X')
            return unavailable;
        if (tunnel.state == 'connected') {
            const link = '/sys/class/net/' + tunnel.device;
            if (type(tunnel.ifindex) != 'int' || tunnel.ifindex <= 0 ||
                +(trim(fs.readfile(link + '/ifindex') || '')) !== tunnel.ifindex ||
                !(+(trim(fs.readfile(link + '/flags') || '0')) & 1))
                return unavailable;
        }
        return {
            available: true,
            state: tunnel.state,
            run_id: runtime.run_id,
            device: tunnel.device,
            retry_in_secs: type(tunnel.retry_in_secs) == 'int' && tunnel.retry_in_secs >= 0 ? tunnel.retry_in_secs : null,
            last_error_code: type(tunnel.last_error_code) == 'string' && match(tunnel.last_error_code, /^(core_-[0-9]+|connection_failed|client_failed|network_not_ready)$/) ? tunnel.last_error_code : null,
        };
    } catch (e) {
        return unavailable;
    }
}

const methods = {
    confirm_router_policy: {
        call: function() {
            const code = system('/etc/init.d/qeli confirm_router >/dev/null 2>&1');
            return { result: code === 0, code };
        }
    },
    forget_retained_secrets: {
        call: function() {
            const code = system('/etc/init.d/qeli forget_retained_secrets >/dev/null 2>&1');
            return { result: code === 0, code };
        }
    },
	service_status: {
		call: function() {
			const code = system('/etc/init.d/qeli status_enabled >/dev/null 2>&1');
			const process = processStatus();
			return {
				enabled: code === 0 ? true : (code === 1 ? false : null),
				running: process ? process.running : null,
				tunnel: tunnelStatus(process),
			};
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
