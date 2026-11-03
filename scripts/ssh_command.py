"""Drain one Paramiko command through a combined channel, without publishing output."""


def run_ssh_command(client, command, timeout=60):
    """Return unstripped UTF-8 output and exit status; close only this command channel.

    Reading stdout then stderr can deadlock on SSH's shared receive window.
    Paramiko merges already-buffered and future stderr into stdout when enabled.
    No stdin is accepted by this helper, so send EOF before waiting for output.
    The supplied timeout remains Paramiko's channel-operation timeout, not a
    remote-process deadline. Closing the channel does not certify remote cleanup.
    """
    stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
    channel = stdout.channel
    try:
        channel.set_combine_stderr(True)
        stdin.close()
        output = stdout.read().decode("utf-8", "replace")
        return output, channel.recv_exit_status()
    finally:
        channel.close()
