# Contributing to qeli — pull request guide

[Русская версия и полное руководство](CONTRIBUTING.md)

Thank you for your interest in qeli. Contributions are accepted through pull requests.

## How to prepare and open a pull request

### 1. Start from `dev`

`dev` is the only target branch for development. `main` contains the released state of
the project. A PR opened directly against `main` will be asked to retarget and rebase
onto `dev`.

Create a fork, then start a dedicated branch from the current `upstream/dev`:

```bash
git clone https://github.com/YOUR_GITHUB_LOGIN/qeli.git
cd qeli
git remote add upstream https://github.com/litvinovtd/qeli.git
git fetch upstream
git switch -c feature/short-name upstream/dev
```

Do not prepare a PR directly on your fork's `main` or `dev`. One branch should address
one related task; submit unrelated fixes as separate PRs.

### 2. Make reviewable commits

- Split the work into logical commits. Code, tests, documentation, and packaging changes
  should be independently reviewable and reversible where practical.
- Do not commit local build output, temporary files, secrets, real server configurations,
  or keys.
- Sign off **every** commit under the DCO with `git commit -s`.
- Before pushing, synchronize your branch with the current `dev`:

```bash
git fetch upstream
git rebase upstream/dev
git push --force-with-lease origin feature/short-name
```

Use `--force-with-lease`, not an unconditional `--force`: it refuses to overwrite remote
work if the branch has unexpectedly changed.

If you forgot the DCO sign-off, fix the last commit with:

```bash
git commit --amend -s --no-edit
```

For several commits, use `git rebase --signoff`. The DCO workflow currently reports
missing sign-offs as an advisory warning, but every commit is still expected to carry a
`Signed-off-by` line and the maintainer may ask you to repair the PR history.

### 3. Include what is needed to review the change

A PR should include the implementation and tests or conformance vectors for new behavior
and bug fixes.

Changes to `CHANGELOG.md` and user documentation are **optional for the PR author**. You
may include them, but if they are absent, the maintainer will add the required release
notes and documentation before publishing a release. If you choose to update them:

- add the changelog entry under the current development version; its source of truth is
  `qeli/Cargo.toml` (0.7.15 at the time of writing);
- document user-visible behavior in both Russian and English;
- add new INI keys and current examples to both `CONFIG.md` files.

For third-party DLLs, drivers, libraries, and other binaries, you must provide the exact
version and source, SHA-256/provenance, license, and third-party notice. Unverified binaries
or binaries built from an unknown source state are not accepted.

Do not create a tag or GitHub Release, and do not publish release artifacts from a PR. The
maintainer performs the final release build and publication after the changes are accepted.

### 4. Test before opening the PR

Run the checks for every affected platform. The complete local gate is:

```bash
scripts/ci-check.sh
```

Platform-specific commands are listed in [the full contributor guide](CONTRIBUTING.md) and
`.github/workflows/ci.yml`. In the PR description, list the commands you actually ran and
their results. If a check requires special hardware, administrator privileges, or the lab
and you could not run it, say so explicitly; do not mark it as completed.

### 5. Open the PR against `dev`

Select these values when creating the PR:

- **base repository:** `litvinovtd/qeli`;
- **base branch:** `dev`;
- **compare branch:** the task branch in your fork.

The PR description should explain:

1. what changed and which problem it solves;
2. how the solution works and which components it affects;
3. how it was tested, including commands, scenarios, and results;
4. known limitations, compatibility risks, and review questions;
5. screenshots for visible UI changes.

Check that the diff contains no accidental files and that every checked test-plan item was
actually completed. For a first-time contributor, GitHub Actions may initially show
`action_required`. This means that the workflow is waiting for maintainer approval; it does
not mean that the tests have already failed.

After review feedback, update the same branch, rerun the relevant checks, and reply briefly
to each point. A PR is ready to merge when conflicts with `dev` are resolved and required
checks are green. Documentation and the changelog can be completed separately before the
release when needed.
