<#
PowerShell helper to create and push an annotated git tag.
Usage examples:
  .\push_tag.ps1 -TagName v0.1.0 -Message "v0.1.0 - Initial release"
  .\push_tag.ps1 -TagName v0.1.0 -Message "..." -Force
  .\push_tag.ps1 -TagName v0.1.0 -Message "..." -PushBranch $true
#>
param(
  [Parameter(Mandatory=$false)] [string] $TagName = "v0.1.0",
  [Parameter(Mandatory=$false)] [string] $Message = "Release $TagName",
  [Parameter(Mandatory=$false)] [string] $Remote = "origin",
  [Parameter(Mandatory=$false)] [switch] $Force,
  [Parameter(Mandatory=$false)] [switch] $PushBranch
)

function Fail($msg){ Write-Error $msg; exit 1 }

$git = Get-Command git -ErrorAction SilentlyContinue
if (-not $git) { Fail "git not found. Install git and re-run this script." }

# Check we're inside a git repo
try { git rev-parse --is-inside-work-tree >$null 2>&1 } catch { Fail "Not a git repository (or git returned an error)." }

# Check tag exists
$tagExists = $false
try {
  git rev-parse -q --verify "refs/tags/$TagName" >$null 2>&1
  if ($LASTEXITCODE -eq 0) { $tagExists = $true }
} catch { }

if ($tagExists -and -not $Force) {
  $ans = Read-Host "Tag $TagName already exists. Overwrite? (y/N)"
  if ($ans -ne 'y') { Write-Host "Cancelled."; exit 0 }
}

if ($tagExists -and $Force) {
  Write-Host "Deleting existing local tag $TagName..."
  git tag -d $TagName
  Write-Host "Deleting existing remote tag $TagName (if present)..."
  git push $Remote :refs/tags/$TagName 2>$null
}

Write-Host "Creating annotated tag $TagName..."
git tag -a $TagName -m "$Message"
if ($LASTEXITCODE -ne 0) { Fail "Failed to create tag." }

Write-Host "Pushing tag to remote $Remote..."
git push $Remote $TagName
if ($LASTEXITCODE -ne 0) { Fail "Failed to push tag to remote." }

if ($PushBranch) {
  $branch = git rev-parse --abbrev-ref HEAD
  Write-Host "Pushing current branch $branch to $Remote..."
  git push $Remote $branch
}

Write-Host "Tag $TagName pushed successfully."