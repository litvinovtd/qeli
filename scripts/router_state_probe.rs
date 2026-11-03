// Opt-in ABI probe: copy into the isolated router crate's examples/ directory.
// It compiles the ACTUAL production opener for each target, not a libc imitation.
// This checks storage only; it does not bypass namespace ownership in the client.
#[path = "../src/state_storage/state_dir.rs"]
mod state_dir;

fn main() -> anyhow::Result<()> {
    let path = std::env::args_os()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("state directory argument required"))?;
    let directory = state_dir::Directory::open(std::path::Path::new(&path))?;
    directory.verify()?;
    println!(
        "accepted owner={} anchored={}",
        directory.owner(),
        directory.journal_path("probe.state")?.display()
    );
    Ok(())
}
