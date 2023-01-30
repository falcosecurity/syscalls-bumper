FROM alpine:latest as builder

LABEL maintainer="cncf-falco-dev@lists.cncf.io"

RUN apk add --no-cache make bash git build-base go

WORKDIR /syscalls-bumper
COPY . .

RUN make build

FROM alpine:latest

COPY --from=builder /syscalls-bumper/build/syscalls-bumper /bin/syscalls-bumper

RUN apk add bash

ENTRYPOINT ["/bin/syscalls-bumper"]
