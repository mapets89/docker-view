#!/bin/sh
set -eu
make build
docker compose build
