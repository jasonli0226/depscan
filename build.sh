#!/bin/sh
export PATH="/usr/local/go/bin:$PATH"
cd "$(dirname "$0")"
go build -o depscan . 2>&1
echo "EXIT_CODE=$?"
