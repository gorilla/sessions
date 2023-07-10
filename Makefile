test: ## Run unit tests. Example: make test
	go test ./...
.PHONY: test

verify: ## Run verifications. Example: make verify
	# https://golangci-lint.run/usage/install/
	golangci-lint run ./...
.PHONY: verify

help: ## Print this help. Example: make help
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)
.PHONY: help
