bumper ?= build/syscalls-bumper

.PHONY: build
build: clean ${bumper}

${bumper}:
	CGO_ENABLED=0 go build -v -buildmode=pie -o $@ .

.PHONY: clean
clean:
	$(RM) -R build
	$(RM) -R driver
	$(RM) -R dist
