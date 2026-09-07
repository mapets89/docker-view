FROM node:26-alpine@sha256:2d984a15c9b54fd0aeb608b8e0d0d83529eb34d2966db27a1fb4f1edc3d298a3 AS frontend
WORKDIR /src/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --ignore-scripts
COPY frontend/ ./
RUN npm run check && npm run build

FROM golang:1.26-alpine@sha256:ce864e7223ac17b1775e6fd0b4c0db580c2eb50e7953a427916379e4b92a1628 AS backend
WORKDIR /src/backend
COPY backend/go.mod backend/go.sum ./
RUN go mod download
COPY backend/ ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/dockerview-server ./cmd/server

FROM alpine:3.24.1@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b
RUN apk add --no-cache libcrypto3=3.5.8-r0 libssl3=3.5.8-r0 \
    && addgroup -S -g 10001 dockerview && adduser -S -D -H -u 10001 -G dockerview dockerview \
    && mkdir -p /app/web /data && chown -R dockerview:dockerview /app /data
COPY --from=backend /out/dockerview-server /usr/local/bin/dockerview-server
COPY --from=frontend /src/frontend/dist/ /app/web/
USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/dockerview-server"]
