# Honeyfile Go Builder
# Cross-compiles the honeyfile for every target platform.
# No Python. No runtime. Single binary per target.
#
# Usage:
#   make build       - Build all targets
#   make build-linux - Build Linux only
#   make clean       - Remove build artifacts
#
# Override config:
#   make build CALLBACK=https://your-c2.com/ingest LEVEL=3 NAME=my_trap

CALLBACK ?= https://127.0.0.1:9999/ingest
LEVEL ?= 1
NAME ?= honeyfile

# All target platforms
TARGETS = \
	windows/amd64 \
	windows/386 \
	windows/arm64 \
	linux/amd64 \
	linux/386 \
	linux/arm64 \
	linux/arm/5 \
	linux/arm/6 \
	linux/arm/7 \
	linux/mips \
	linux/mipsle \
	linux/mips64 \
	linux/mips64le \
	linux/riscv64 \
	darwin/amd64 \
	darwin/arm64

# Output directory
OUT = build

.PHONY: all clean build build-linux build-windows build-darwin

all: clean build

build: $(TARGETS)

# Template: replace {{VAR}} in main.go and compile
define BUILD_TARGET
$(OUT)/honeyfile_$(1)_$(2)$(3):
	@mkdir -p $(OUT)
	@echo "  [+] Building $$@"
	@sed 's|{{CALLBACK_URL}}|$(CALLBACK)|g; s|{{LEVEL}}|$(LEVEL)|g; s|{{TRAP_NAME}}|$(NAME)|g' main.go > /tmp/honeyfile_build_$(1)_$(2).go
	@GOOS=$(1) GOARCH=$(2) GOARM=$(4) go build -ldflags="-s -w" \
		-o $$@ /tmp/honeyfile_build_$(1)_$(2).go 2>/dev/null && \
		echo "  [✓] $$@ ($$(wc -c < $$@) bytes)" || \
		echo "  [✗] $$@ build failed"
	@rm -f /tmp/honeyfile_build_$(1)_$(2).go
endef

# Windows targets
windows/amd64:
	$(eval GOOS=windows GOARCH=amd64 GOARM= EXT=.exe)
	$(call BUILD_TARGET,windows,amd64,.exe)

windows/386:
	$(eval GOOS=windows GOARCH=386 GOARM= EXT=.exe)
	$(call BUILD_TARGET,windows,386,.exe)

windows/arm64:
	$(eval GOOS=windows GOARCH=arm64 GOARM= EXT=.exe)
	$(call BUILD_TARGET,windows,arm64,.exe)

# Linux targets
linux/amd64:
	$(call BUILD_TARGET,linux,amd64,)

linux/386:
	$(call BUILD_TARGET,linux,386,)

linux/arm64:
	$(call BUILD_TARGET,linux,arm64,)

linux/arm/5:
	$(call BUILD_TARGET,linux,arm,/5,5)

linux/arm/6:
	$(call BUILD_TARGET,linux,arm,/6,6)

linux/arm/7:
	$(call BUILD_TARGET,linux,arm,/7,7)

linux/mips:
	$(call BUILD_TARGET,linux,mips,)

linux/mipsle:
	$(call BUILD_TARGET,linux,mipsle,)

linux/mips64:
	$(call BUILD_TARGET,linux,mips64,)

linux/mips64le:
	$(call BUILD_TARGET,linux,mips64le,)

linux/riscv64:
	$(call BUILD_TARGET,linux,riscv64,)

# macOS targets
darwin/amd64:
	$(call BUILD_TARGET,darwin,amd64,)

darwin/arm64:
	$(call BUILD_TARGET,darwin,arm64,)

# Convenience targets
build-windows: windows/amd64 windows/386 windows/arm64
build-linux: linux/amd64 linux/386 linux/arm64 linux/arm/5 linux/arm/6 linux/arm/7 linux/mips linux/mipsle
build-darwin: darwin/amd64 darwin/arm64

clean:
	@rm -rf $(OUT)
	@echo "  [✓] Build directory cleaned"

list:
	@echo "Available targets:"
	@echo "  make build          - Build all 15 platforms"
	@echo "  make build-linux    - Linux (8 targets)"
	@echo "  make build-windows  - Windows (3 targets)"
	@echo "  make build-darwin   - macOS (2 targets)"  
	@echo ""
	@echo "Config:"
	@echo "  CALLBACK=https://c2.com/ingest"
	@echo "  LEVEL=1 (1-5)"
	@echo "  NAME=trap_name"
