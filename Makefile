SHELL := /bin/sh
.DEFAULT_GOAL := help

.PHONY: help bootstrap verify-spec dev down logs ps fmt lint test test-unit test-integration web-install web-dev web-build web-test migrate-up migrate-down openapi-validate compose-config clean

help:
	@printf '%s\n' \
	  'bootstrap          Generate .env and install frontend dependencies' \
	  'dev                Build and start the complete local Foundation stack' \
	  'down               Stop the local stack' \
	  'fmt                Format Go code and run frontend lint' \
	  'lint               Run Go vet, golangci-lint, frontend lint, and typecheck' \
	  'test               Run unit and frontend tests' \
	  'test-integration   Run live dependency integration tests' \
	  'openapi-validate   Validate OpenAPI 3.1' \
	  'verify-spec        Reconstruct and verify the authoritative DOCX'

bootstrap:
	./scripts/dev-env.sh
	npm install --no-audit --no-fund

verify-spec:
	./scripts/verify-spec.sh

compose-config:
	docker compose config --quiet

dev: verify-spec compose-config
	docker compose up --build -d --wait
	@echo 'Web:      http://localhost:3000'
	@echo 'API:      http://localhost:8080'
	@echo 'Keycloak: http://keycloak.localhost:8081'

ps:
	docker compose ps

logs:
	docker compose logs -f --tail=200

down:
	docker compose down --remove-orphans

fmt:
	gofmt -w $$(find apps internal packages tests -name '*.go' -type f)
	npm --workspace apps/web run lint

lint:
	go vet ./...
	golangci-lint run ./...
	npm --workspace apps/web run lint
	npm --workspace apps/web run typecheck

test: test-unit web-test

test-unit:
	go test -race -count=1 ./apps/... ./internal/... ./packages/...

web-install:
	npm install --no-audit --no-fund

web-dev:
	npm --workspace apps/web run dev

web-build:
	npm --workspace apps/web run build

web-test:
	npm --workspace apps/web run test

migrate-up:
	docker compose run --rm migrate -path /migrations -database "$$MIGRATION_DATABASE_URL" up

migrate-down:
	docker compose run --rm migrate -path /migrations -database "$$MIGRATION_DATABASE_URL" down 1

openapi-validate:
	npx --yes @stoplight/spectral-cli@6.15.0 lint docs/api/openapi.yaml --ruleset .spectral.yaml

test-integration:
	./scripts/integration-test.sh

clean:
	rm -rf apps/web/.next apps/web/coverage .runtime
