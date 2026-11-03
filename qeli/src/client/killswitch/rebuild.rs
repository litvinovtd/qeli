//! A crashed kill-switch must remain closed while its ordinary chain is rebuilt.
//! Exact commented DROP guards survive a second crash and are removed only after
//! all requested families have completed setup. No saved name authorizes a flush.
use super::{chain_exists, chain_for, Context};

pub(super) const COMMENT_PREFIX: &str = "qeli-ks-rebuild:";
fn rule<'a>(hook: &'a str, comment: &'a str, action: &'a str) -> Vec<&'a str> {
    let mut args = vec![action, hook];
    if action == "-I" {
        args.push("1");
    }
    args.extend(["-m", "comment", "--comment", comment, "-j", "DROP"]);
    args
}
fn present(context: &Context, path: &str, hook: &str, comment: &str) -> anyhow::Result<bool> {
    context.present_checked(path, &rule(hook, comment, "-C"))
}
fn install(context: &Context, path: &str, hook: &str, comment: &str) -> anyhow::Result<()> {
    if !present(context, path, hook, comment)? {
        let error = context.ipt(path, &rule(hook, comment, "-I")).err();
        anyhow::ensure!(
            present(context, path, hook, comment)?,
            "cannot install kill-switch rebuild guard in {hook}: {error:?}"
        );
    }
    Ok(())
}

/// Arm before the caller tears down either family's prior ruleset. An interrupted
/// previous rebuild can leave only these exact guards, with no ordinary chain.
pub(super) fn arm(context: &Context, path: &str, tun: &str, forward: bool) -> anyhow::Result<bool> {
    let comment = format!("{COMMENT_PREFIX}{tun}");
    let chain = chain_for(tun);
    let previous = chain_exists(context, path, &chain)?;
    let output_guard = present(context, path, "OUTPUT", &comment)?;
    let forward_guard = present(context, path, "FORWARD", &comment)?;
    if !previous && !output_guard && !forward_guard {
        return Ok(false);
    }
    let old_forward = context.present_checked(path, &["-C", "FORWARD", "-j", &chain])?;
    // Guard the entire hook, including former allowances: availability can pause,
    // but old rules can never be replaced by an unprotected physical default.
    install(context, path, "OUTPUT", &comment)?;
    if forward || old_forward || forward_guard {
        install(context, path, "FORWARD", &comment)?;
    }
    Ok(true)
}

/// Called only after every required family is armed, or on an explicit clean stop.
/// Refusal here leaves the new normal chain intact; never roll it back afterwards.
pub(super) fn clear(context: &Context, path: &str, tun: &str) -> anyhow::Result<()> {
    let comment = format!("{COMMENT_PREFIX}{tun}");
    for hook in ["OUTPUT", "FORWARD"] {
        for _ in 0..8 {
            if !present(context, path, hook, &comment)? {
                break;
            }
            let _ = context.ipt(path, &rule(hook, &comment, "-D"));
        }
        anyhow::ensure!(
            !present(context, path, hook, &comment)?,
            "kill-switch rebuild guard remains in {hook}; protection retained"
        );
    }
    Ok(())
}
