SHELL=/usr/bin/env bash
.SHELLFLAGS=-o pipefail -ec
.DEFAULT_GOAL := test

.PHONY: build
build:
	go build -o poutine .

ci: fmt test lint smoke-test

test:
	go test ./... -cover

fmt:
	go fmt ./...

lint:
	golangci-lint run

.PHONY: smoke-test
smoke-test: smoke-test-build smoke-test-run
	@echo "✅ All smoke tests passed!"

.PHONY: smoke-test-build
smoke-test-build:
	@echo "Setting up smoke test environment..."
	@if [ -d ".smoke-test" ]; then rm -rf .smoke-test; fi
	@mkdir -p .smoke-test
	@cp -r . .smoke-test/poutine-build
	@cd .smoke-test/poutine-build && rm -f .poutine.yml
	@cd .smoke-test/poutine-build && go build -o ../poutine .
	@echo "✅ Smoke test environment ready"

.PHONY: smoke-test-run
smoke-test-run:
	@if [ ! -f ".smoke-test/poutine" ]; then echo "❌ Run 'make smoke-test-build' first"; exit 1; fi
	@echo "Running smoke tests..."
	@cd .smoke-test && \
		echo "Testing CLI help..." && \
		./poutine --help > help.txt && \
		grep -q "analyze_org" help.txt && \
		grep -q "analyze_repo" help.txt && \
		grep -q "format.*pretty, json, sarif" help.txt && \
		echo "✅ CLI help test passed" && \
		echo "Testing pretty format..." && \
		timeout 120 ./poutine --token $$(gh auth token) analyze_org messypoutine --format=pretty --quiet > pretty.txt 2>/dev/null && \
		grep -q "REPOSITORY" pretty.txt && \
		grep -q "DETAILS" pretty.txt && \
		grep -q "URL" pretty.txt && \
		grep -q "Summary of findings:" pretty.txt && \
		grep -q "┌" pretty.txt && \
		grep -q "│" pretty.txt && \
		echo "✅ Pretty format test passed" && \
		echo "Testing JSON format..." && \
		timeout 120 ./poutine --token $$(gh auth token) analyze_org messypoutine --format=json --quiet > output.json 2>/dev/null && \
		jq -e '.findings' output.json > /dev/null && \
		jq -e '.rules' output.json > /dev/null && \
		jq -e '.findings[0].rule_id' output.json > /dev/null && \
		jq -e '.findings[0].purl' output.json > /dev/null && \
		echo "✅ JSON format test passed" && \
		echo "Testing SARIF format..." && \
		timeout 120 ./poutine --token $$(gh auth token) analyze_org messypoutine --format=sarif --quiet > output.sarif 2>/dev/null && \
		jq -e '.["$$schema"]' output.sarif > /dev/null && \
		jq -e '.version' output.sarif > /dev/null && \
		jq -e '.runs' output.sarif > /dev/null && \
		echo "✅ SARIF format test passed" && \
		echo "Testing Unicode table rendering..." && \
		grep -c "┌" pretty.txt | grep -q "[1-9]" && \
		grep -c "├" pretty.txt | grep -q "[1-9]" && \
		grep -c "└" pretty.txt | grep -q "[1-9]" && \
		grep -c "│" pretty.txt | grep -q "[1-9]" && \
		grep -q "RULE ID.*RULE NAME.*FAILURES.*STATUS" pretty.txt && \
		echo "✅ Table rendering test passed"

.PHONY: smoke-test-clean
smoke-test-clean:
	@rm -rf .smoke-test
	@echo "✅ Smoke test environment cleaned"
