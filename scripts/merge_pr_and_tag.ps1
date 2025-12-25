<#
Run this script locally (PowerShell) to merge a PR and create a release tag.
Usage (examples):
  .\scripts\merge_pr_and_tag.ps1 -Pr 2 -Tag v0.1.0 -Message "v0.1.0 - Initial release"

Prerequisites:
  - Git installed and repo is clean
  - GitHub CLI `gh` installed and authenticated
  - You have permission to merge PRs and push tags
#>
param(
  [Parameter(Mandatory=$true)][int]$Pr,
  [Parameter(Mandatory=$true)][string]$Tag,
  [Parameter(Mandatory=$false)][string]$Message = "Release $Tag"
)

Write-Host "Merging PR #$Pr..."
gh pr merge $Pr --merge --delete-branch --body "Merged by $env:USERNAME via scripts/merge_pr_and_tag.ps1"

if ($LASTEXITCODE -ne 0) {
  Write-Error "Failed to merge PR #$Pr. Aborting."
  exit $LASTEXITCODE
}

Write-Host "Creating annotated tag $Tag..."
git tag -a $Tag -m "$Message"
if ($LASTEXITCODE -ne 0) { Write-Error "git tag failed"; exit $LASTEXITCODE }

git push origin $Tag
if ($LASTEXITCODE -ne 0) { Write-Error "Failed to push tag $Tag"; exit $LASTEXITCODE }

Write-Host "Tag pushed. You can now check Actions for a packaging run triggered by $Tag."
Write-Host "To list recent runs: gh run list --limit 20"
Write-Host "To view artifacts for a run: gh run view <run-id> --json artifacts --jq .artifacts"

Write-Host "Done."