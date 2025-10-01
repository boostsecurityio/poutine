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
		echo "Testing JSON format with messypoutine/gravy-overflow analysis..." && \
		timeout 120 ./poutine --token $$(gh auth token) analyze_repo messypoutine/gravy-overflow --format=json --quiet > output.json 2>/dev/null && \
		jq -e '.findings | length > 10' output.json > /dev/null && \
		jq -e '.rules | length > 5' output.json > /dev/null && \
		jq -e '.rules | has("injection")' output.json > /dev/null && \
		jq -e '.rules | has("debug_enabled")' output.json > /dev/null && \
		jq -e '.rules | has("untrusted_checkout_exec")' output.json > /dev/null && \
		jq -e '.findings | map(select(.rule_id == "injection")) | length > 0' output.json > /dev/null && \
		jq -e '.findings | map(select(.rule_id == "debug_enabled")) | length > 0' output.json > /dev/null && \
		jq -e '.findings | map(select(.rule_id == "untrusted_checkout_exec")) | length > 0' output.json > /dev/null && \
		jq -e '.findings[] | select(.purl == "pkg:github/messypoutine/gravy-overflow")' output.json > /dev/null && \
		echo "✅ JSON format test passed with expected gravy-overflow findings" && \
		echo "Testing pretty format..." && \
		timeout 120 ./poutine --token $$(gh auth token) analyze_repo messypoutine/gravy-overflow --format=pretty --quiet > pretty.txt 2>/dev/null && \
		grep -q "Rule: CI Runner Debug Enabled" pretty.txt && \
		grep -q "Rule: Injection with Arbitrary External Contributor Input" pretty.txt && \
		grep -q "Rule: Arbitrary Code Execution from Untrusted Code Changes" pretty.txt && \
		grep -q "messypoutine/gravy-overflow" pretty.txt && \
		grep -q "ACTIONS_RUNNER_DEBUG" pretty.txt && \
		grep -q "github.event.comment.body" pretty.txt && \
		grep -q "Summary of findings:" pretty.txt && \
		echo "✅ Pretty format test passed with expected content" && \
		echo "Testing SARIF format..." && \
		timeout 120 ./poutine --token $$(gh auth token) analyze_repo messypoutine/gravy-overflow --format=sarif --quiet > output.sarif 2>/dev/null && \
		jq -e '.["$$schema"]' output.sarif > /dev/null && \
		jq -e '.version == "2.1.0"' output.sarif > /dev/null && \
		jq -e '.runs | length == 1' output.sarif > /dev/null && \
		jq -e '.runs[0].results | length > 10' output.sarif > /dev/null && \
		echo "✅ SARIF format test passed with expected structure" && \
		echo "Testing Unicode table rendering with tablewriter v1.0.9..." && \
		grep -c "┌" pretty.txt | grep -q "[1-9]" && \
		grep -c "├" pretty.txt | grep -q "[1-9]" && \
		grep -c "└" pretty.txt | grep -q "[1-9]" && \
		grep -c "│" pretty.txt | grep -q "[1-9]" && \
		grep -q "debug_enabled.*CI Runner Debug Enabled.*[1-9].*Failed" pretty.txt && \
		grep -q "injection.*Injection with Arbitrary.*[1-9].*Failed" pretty.txt && \
		grep -q "untrusted_checkout_exec.*Arbitrary Code Execution.*[1-9].*Failed" pretty.txt && \
		echo "✅ Table rendering test passed with expected summary data"

.PHONY: smoke-test-clean
smoke-test-clean:
	@rm -rf .smoke-test
	@echo "✅ Smoke test environment cleaned"
