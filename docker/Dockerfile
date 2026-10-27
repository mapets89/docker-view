FROM node:26-alpine@sha256:2d984a15c9b54fd0aeb608b8e0d0d83529eb34d2966db27a1fb4f1edc3d298a3 AS frontend
WORKDIR /src/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --ignore-scripts
COPY frontend/ ./
RUN npm run check && npm run build

FROM golang:1.26.10-alpine@sha256:a2012b4a1d1f9f7e9f44e0d39b805a901e856b1dd80b4e6ee4338db547050308 AS backend
WORKDIR /src/backend
COPY backend/go.mod backend/go.sum ./
RUN go mod download
COPY backend/ ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/dockerview-server ./cmd/server

FROM alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
RUN apk add --no-cache libcrypto3 libssl3 \
    && addgroup -S -g 10001 dockerview && adduser -S -D -H -u 10001 -G dockerview dockerview \
    && mkdir -p /app/web /data && chown -R dockerview:dockerview /app /data
COPY --from=backend /out/dockerview-server /usr/local/bin/dockerview-server
COPY --from=frontend /src/frontend/dist/ /app/web/
USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/dockerview-server"]
