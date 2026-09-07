#!/bin/sh
set -eu
docker compose -f compose.yml -f compose.dev.yml up --build
