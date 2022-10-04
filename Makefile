bumper ?= build/bumper

.PHONY: build
build: clean ${bumper}

${bumper}:
	CGO_ENABLED=0 go build -v -buildmode=pie -ldflags '${LDFLAGS}' -o $@ .

.PHONY: release
release: clean
	CGO_ENABLED=0 LDFLAGS="${LDFLAGS}" $(GORELEASER) release

.PHONY: clean
clean:
	$(RM) -R dist
	$(RM) -R build
