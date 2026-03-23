BINARY   = nightcloak
VERSION  = $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS  = -s -w
TARGETS  = darwin/amd64 darwin/arm64 linux/amd64 linux/arm64 windows/amd64

.PHONY: build build-all clean test

build:
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o bin/$(BINARY) cmd/nightcloak/main.go

test:
	go test ./... -v -count=1

build-all:
	@mkdir -p dist
	@for target in $(TARGETS); do \
		os=$$(echo $$target | cut -d/ -f1); \
		arch=$$(echo $$target | cut -d/ -f2); \
		ext=""; \
		if [ "$$os" = "windows" ]; then ext=".exe"; fi; \
		out="dist/$(BINARY)-$$os-$$arch$$ext"; \
		echo "Building $$out ..."; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -ldflags "$(LDFLAGS)" -o $$out cmd/nightcloak/main.go; \
	done
	@echo "Done. Binaries in dist/"

clean:
	rm -rf bin/$(BINARY) dist/
