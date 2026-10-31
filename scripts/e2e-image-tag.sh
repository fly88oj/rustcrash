#!/bin/bash
# Content-addressed e2e image tagging, shared by the docker suites.
#
# The engine suites (docker-engine, docker-interop, docker-matrix,
# docker-reality, docker-shellcrash) share ONE image built from
# tests/docker-engine/Dockerfile.engine; docker-cluster builds a sibling
# from Dockerfile.cluster. Under the old fixed tag + "skip build if
# present" scheme:
#   - parallel suites raced the same tag with different content, and
#   - a stale image silently tested yesterday's engine
#     (E2E_FORCE_BUILD existed to fight exactly that).
#
# The tag now encodes WHAT the image is built from — a content hash of
# every tree the Dockerfile COPYs — so:
#   - content changed  -> new tag -> rebuild (staleness impossible)
#   - content same     -> tag exists -> skip build (cache-friendly)
#   - parallel suites -> identical content lands on the identical tag
#                        and an flock builds it exactly once; divergent
#                        content (worktree vs committed tree) gets
#                        distinct tags and never races.
#
# Usage (from a suite's run.sh, with COMPOSE_FILE already set):
#   . "$(dirname "${BASH_SOURCE[0]}")/../scripts/e2e-image-tag.sh"
#   ensure_engine_image            # archive of HEAD, or worktree by knob
#   ensure_engine_image worktree   # force the working tree
#   # -> exports ENGINE_IMAGE_TAG="<name>:c<hash>"; compose files use
#   #    image: ${ENGINE_IMAGE_TAG:-<name>:latest}
#
# Knobs (env), same semantics the suites had individually:
#   E2E_FORCE_BUILD=1          rebuild even when the tag exists
#   E2E_WORKING_TREE_BUILD=1   build from the working tree instead of a
#                              git-archive of HEAD (local iteration)
#   E2E_IMAGE_NAME             image name (default docker-engine-rustcrash)
#   E2E_IMAGE_DOCKERFILE       dockerfile path relative to the repo root
#                              (default tests/docker-engine/Dockerfile.engine)

E2E_IMAGE_NAME="${E2E_IMAGE_NAME:-docker-engine-rustcrash}"
E2E_IMAGE_DOCKERFILE="${E2E_IMAGE_DOCKERFILE:-tests/docker-engine/Dockerfile.engine}"
E2E_IMAGE_SERVICE="${E2E_IMAGE_SERVICE:-rustcrash}"
E2E_IMAGE_LOCK="${E2E_IMAGE_LOCK:-/tmp/rustcrash-e2e-image.lock}"

_e2e_root() {
    git -C "$(dirname "${BASH_SOURCE[0]}")/.." rev-parse --show-toplevel 2>/dev/null \
        || dirname "$(dirname "$(dirname "${BASH_SOURCE[0]}")")"
}

# Stable hash of everything an image build consumes from the tree at $1:
# the source trees the Dockerfile COPYs, the manifests, and the
# Dockerfile itself. Content-only (no mtimes), so a git-archive of HEAD
# and a clean working tree hash identically and share one image.
# certs/ subtrees are excluded: they are host-generated, git-ignored,
# and therefore absent from archive builds. .mimosa/ (the git-hook's
# per-session state) is excluded: it mutates on every tooling run, is
# never a build input, and otherwise forked the worktree tag from the
# archive tag on a clean tree — two full image builds for one tree.
_e2e_content_hash() {
    local dir="$1" files
    files=$(cd "$dir" && {
        find engine core cmd tests -type f ! -path '*/certs/*' ! -path '*/.mimosa/*' | LC_ALL=C sort
        echo Cargo.toml
        echo Cargo.lock
        echo "$E2E_IMAGE_DOCKERFILE"
    })
    {
        printf '%s\n' "$files"
        while IFS= read -r f; do
            sha256sum "$dir/$f" 2>/dev/null | cut -d' ' -f1 || echo missing
        done <<< "$files"
    } | sha256sum | cut -c1-16
}

# Which tree to build from: a git-archive of HEAD (the default — a
# build from a half-edited working tree is a coin flip when several
# suites run in parallel), the working tree when asked, or the working
# tree when git is not usable.
_e2e_resolve_source() {
    if [ "${E2E_WORKING_TREE_BUILD:-0}" = "1" ]; then
        echo worktree
    elif git -C "$(_e2e_root)" rev-parse --git-dir >/dev/null 2>&1; then
        echo archive
    else
        echo worktree
    fi
}

# Export ENGINE_IMAGE_TAG for the resolved source; build the image when
# that tag is missing (or E2E_FORCE_BUILD=1), under a host-wide flock
# so parallel suites build each distinct image exactly once.
ensure_engine_image() {
    local source="${1:-$(_e2e_resolve_source)}"
    # Every local gets an initial value: under `set -u` (the run.sh
    # scripts enable it), a bare `local x` stays "unbound" on expansion
    # in this bash — which killed the worktree path at the export_dir
    # references below.
    local root="" build_dir="" export_dir="" tag=""
    root="$(_e2e_root)"
    build_dir="$root"

    if [ "$source" = archive ]; then
        export_dir=$(mktemp -d /tmp/rustcrash-e2e-export.XXXXXX)
        if ! git -C "$root" archive HEAD | tar -x -C "$export_dir" 2>/dev/null; then
            rm -rf "$export_dir"
            export_dir=""
            source=worktree   # no usable git: fall back; tag follows content
        else
            build_dir="$export_dir"
        fi
    fi

    tag="c$(_e2e_content_hash "$build_dir")"
    ENGINE_IMAGE_TAG="$E2E_IMAGE_NAME:$tag"
    export ENGINE_IMAGE_TAG

    if [ "${E2E_FORCE_BUILD:-0}" != "1" ] \
        && docker image inspect "$ENGINE_IMAGE_TAG" >/dev/null 2>&1; then
        echo "--- image $ENGINE_IMAGE_TAG present (reuse)"
        [ -n "$export_dir" ] && rm -rf "$export_dir"
        return 0
    fi

    echo "--- building image $ENGINE_IMAGE_TAG (from $source)"
    (
        flock 9
        # Re-check under the lock: a parallel suite may have finished
        # the identical build while we waited.
        if [ "${E2E_FORCE_BUILD:-0}" != "1" ] \
            && docker image inspect "$ENGINE_IMAGE_TAG" >/dev/null 2>&1; then
            exit 0
        fi
        if [ -n "$export_dir" ]; then
            docker build --quiet -t "$ENGINE_IMAGE_TAG" \
                -f "$root/$E2E_IMAGE_DOCKERFILE" "$export_dir" \
                || exit 1
        else
            docker compose -f "$COMPOSE_FILE" build "$E2E_IMAGE_SERVICE" --quiet \
                || exit 1
        fi
    ) 9>"$E2E_IMAGE_LOCK" || {
        rm -rf "$export_dir"
        echo "image build failed"
        return 1
    }
    rm -rf "$export_dir"
    return 0
}
