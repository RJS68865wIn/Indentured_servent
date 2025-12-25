# Release readiness notes

Status: READY ✅

What I prepared for you:

- Updated CI to install `requirements.txt` and skip Windows-only deps on Linux (environment markers). ✅
- Added `requirements.txt` (copied from `requirements.txt.txt`). ✅
- Added `scripts/merge_pr_and_tag.ps1`: a convenient one-command helper to merge a PR, create an annotated tag, push it, and give next steps to check Actions for packaging artifacts. Use it locally when ready.

Suggested flow (single-user command):

1. Run the merge-and-tag helper locally (example):

   ```powershell
   .\scripts\merge_pr_and_tag.ps1 -Pr 2 -Tag v0.1.0 -Message "v0.1.0 - Initial release"
   ```

2. Watch GitHub Actions for the package job triggered by the pushed tag. If you want, paste the package run id here and I will inspect the artifact list and help download or publish it.

Notes & safety
- The script expects `gh` and `git` to be installed and authenticated locally. It does not perform elevated or privileged operations on your behalf.
- If you prefer I *merge manually*, I can't run `gh` here but I can provide the exact command to run and follow the Actions run for you.

If you'd like, I can also prepare a short release draft body (to paste into the GitHub Releases UI) and a follow-up checklist for publishing the artifacts publicly.
