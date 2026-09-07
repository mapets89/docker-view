.PHONY: dev build test lint typecheck security compose-up compose-down clean backend-test frontend-test
GOCACHE ?= /tmp/dockerview-go-cache
dev:
	docker compose -f compose.yml -f compose.dev.yml up --build
build:
	cd frontend && npm run build
	cd backend && GOCACHE=$(GOCACHE) go build ./cmd/...
test: backend-test frontend-test
backend-test:
	cd backend && GOCACHE=$(GOCACHE) go test -race ./...
frontend-test:
	cd frontend && npm run check
lint:
	cd backend && test -z "$$(gofmt -l .)" && GOCACHE=$(GOCACHE) go vet ./...
	cd frontend && npm run lint && npm run format:check
typecheck:
	cd frontend && npm run typecheck && npm run check
security:
	./scripts/security.sh
compose-up:
	docker compose up -d --build
compose-down:
	docker compose down
clean:
	cd frontend && rm -rf dist .astro
	rm -rf backend/bin
