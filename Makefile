bumper ?= build/bumper

.PHONY: build
build: clean ${bumper}

${bumper}:
	CGO_ENABLED=0 go build -v -buildmode=pie -ldflags '${LDFLAGS}' -o $@ .

.PHONY: clean
clean:
	$(RM) -R build
	$(RM) -R driver
