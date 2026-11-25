# Working rules for Claude sessions

Loaded automatically by Claude Code from `.claude/rules/`. The same file is in every repo; change it in all of them or none. Source: the Nov 25, 2026 dev efficiency review (rules S1 to S13).

## Before starting
- S1. Probe access first: confirm you can clone and push here, that the GitHub API answers, and that every connector or upload host the task needs is reachable. Report everything missing in one message before planning.
- S2. Never build in a repo or path you can't push to. If the target is unreachable, stop at a written plan.
- S5. Build only on this repo's default branch. Code that exists only in a zip, a drive folder or a chat library gets imported to a branch first.
- S12. Check CI on the default branch before opening a PR. If it is already red, say so first and don't take ownership of failures you didn't cause.

## While working
- S3. Every blocking question carries a default and a deadline ("If I don't hear by X, I'll do Y"). Keep working on everything that doesn't depend on the answer.
- S4. When a date in a plan, queue or config has passed, say so in the first line of your next report.
- S6. Save anything another session needs to the repo or the shared project folder as soon as it exists. Scratch space is lost.
- S7. Before writing to a live system (store, tracker, this repo), check who else changed it in the last 24 hours. If another agent or app is mid-edit, stop and report.
- S8. Get the target reference before any creative generation. After one miss, switch to image-to-image or stop.
- S9. A one-word ask ("Next", "Self-prompt") means the next open step of the current task. State that assumption in one line rather than asking.
- S10. One tracker of record per project. Any mirror is updated in the same step or labeled as a snapshot.

## Before pushing
- S11. Run this repo's own CI command locally (see `build-and-test.md` where present). If local and CI disagree, trust CI and note the difference.
- S13. Log every new wall (proxy block, quota, missing app install) once, with its workaround, so the next session doesn't rediscover it.

## Repo conventions
See `docs/repo-conventions.md`.
