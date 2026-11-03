# Qeli repository instructions

## Branch policy

- The only permanent branches, locally and on GitHub, are `main`, `dev`, and `blog`.
- All agent-authored development, fixes, tests, documentation and release preparation happen on `dev` in the primary checkout.
- Do not create or push any other development branch, including `codex/*`, feature, hotfix, maintenance or release branches. Do not create a worktree that creates such a branch.
- Keep `main` and `blog` unchanged unless the user explicitly requests work on them or a release merge.
- User-approved exception: Dependabot may create temporary head branches for open pull requests targeting `dev`. Remove those temporary branches after the PR is merged and its commits are verified to be included in `dev`. Do not disable Dependabot or its security notifications merely to enforce the permanent-branch list.
- Existing detached worktrees may be retained as historical build/audit snapshots; do not use them for new development.
- This policy does not itself authorize commits, code pushes, merges or release publication.
