#!/bin/sh
set -eu

repository=$1
revision=$2
destination=$3

if [ -d "$destination" ]; then
    actual=$(git -C "$destination" rev-parse HEAD)
    if [ "$actual" != "$revision" ]; then
        printf 'Dependency revision mismatch: %s\n' "$destination" >&2
        exit 1
    fi
    exit 0
fi

mkdir -p "$(dirname "$destination")"
temporary=$(mktemp -d "${destination}.fetch.XXXXXX")
trap 'rm -rf -- "$temporary"' EXIT HUP INT TERM
git -C "$temporary" init -q
git -C "$temporary" remote add origin "$repository"
GIT_TERMINAL_PROMPT=0 git -C "$temporary" -c http.lowSpeedLimit=1024 -c http.lowSpeedTime=60 fetch --depth=1 origin "$revision"
git -C "$temporary" checkout -q --detach FETCH_HEAD
test "$(git -C "$temporary" rev-parse HEAD)" = "$revision"
mv -T "$temporary" "$destination"
trap - EXIT HUP INT TERM
