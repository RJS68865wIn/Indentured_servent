#!/usr/bin/env bash
# Simple helper to create and push an annotated git tag.
# Usage: ./push_tag.sh v0.1.0 "Release message" [--force] [--push-branch]
set -euo pipefail
TAG=${1:-v0.1.0}
MSG=${2:-"Release ${TAG}"}
FORCE=false
PUSH_BRANCH=false
for arg in "${@:3}"; do
  case "$arg" in
    --force) FORCE=true ;; 
    --push-branch) PUSH_BRANCH=true ;;
  esac
done

if ! command -v git >/dev/null 2>&1; then
  echo "git not found. Install git and re-run this script." >&2
  exit 1
fi

git rev-parse --is-inside-work-tree >/dev/null 2>&1 || { echo "Not a git repository" >&2; exit 1; }

if git rev-parse -q --verify "refs/tags/$TAG" >/dev/null 2>&1; then
  if [ "$FORCE" = true ]; then
    echo "Deleting existing tag $TAG locally and remotely..."
    git tag -d "$TAG" || true
    git push origin :refs/tags/$TAG || true
  else
    read -p "Tag $TAG exists — overwrite? (y/N) " yn
    if [ "$yn" != "y" ]; then
      echo "Cancelled."; exit 0
    fi
  fi
fi

echo "Creating annotated tag $TAG..."
git tag -a "$TAG" -m "$MSG"

echo "Pushing tag to origin..."
git push origin "$TAG"

if [ "$PUSH_BRANCH" = true ]; then
  BRANCH=$(git rev-parse --abbrev-ref HEAD)
  echo "Pushing branch $BRANCH to origin..."
  git push origin "$BRANCH"
fi

echo "Tag $TAG pushed successfully."