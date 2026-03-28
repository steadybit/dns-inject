.PHONY: help audit tidy build generate fmt clean

## help: print this help message
help:
	@echo 'Usage:'
	@sed -n 's/^##//p' ${MAKEFILE_LIST} | column -t -s ':' | sed -e 's/^/ /'

## audit: run formatting checks, vet, staticcheck, tests, and module verification
audit: generate
	gofmt -l .
	GOOS=linux go vet ./...
	@if [ "$$(uname -s)" = "Linux" ]; then go run honnef.co/go/tools/cmd/staticcheck@latest ./...; fi
	@if [ "$$(uname -s)" = "Linux" ]; then go test -race -vet=off -timeout 5m ./...; else	go test -race -vet=off -timeout 5m ./e2e/...; fi
	go mod verify

## tidy: format code and tidy modules
tidy:
	go fmt ./...
	go mod tidy -v

## build: build using goreleaser
build:
	GOOS=linux goreleaser build --clean --snapshot --single-target -o dns-inject

## generate: regenerate eBPF objects
generate:
	go generate ./ebpf/...

## fmt: format C and Go source
fmt:
	gofmt -w .
	clang-format -i ebpf/*.c ebpf/*.h

## clean: remove build artifacts
clean:
	rm -rf dist/ dns-inject
