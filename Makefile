# set mac-only linker flags only for go test (not global)
UNAME_S := $(shell uname -s)
TEST_ENV :=
ifeq ($(UNAME_S),Darwin)
  TEST_ENV = CGO_LDFLAGS=-w
endif

TEST_FLAGS := -race -count=1
.PHONY: build-debug
build-debug:
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build -trimpath -ldflags "-s -w" -o dist/debug ./cmd/debug

.PHONY: debug
debug:
	go run ./cmd/debug -data ./fixtures/debug-data.json -policy ./fixtures/debug-policy.rego

.PHONY: test
test:
	$(TEST_ENV) go test $(TEST_FLAGS) ./...

.PHONY: test-unit
test-unit:
	$(TEST_ENV) go test $(TEST_FLAGS) ./internal/...

.PHONY: test-e2e
test-e2e:
	$(TEST_ENV) go test $(TEST_FLAGS) ./e2e
