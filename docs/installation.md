# Installation

Run `cp .env.example .env` and `docker compose up -d --build`, then open `http://localhost:8080`. The secret init service runs once, while named volumes retain SQLite and Gateway credentials.

On Linux, obtain the socket group with `stat -c '%g' /var/run/docker.sock` and set `DOCKER_GID` if it is not `0`. Do not solve socket permissions with `privileged: true` or a world-writable socket. For remote access, use a TLS reverse proxy and a private/VPN network.
