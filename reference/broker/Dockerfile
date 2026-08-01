# syntax=docker/dockerfile:1
FROM golang:1.24-alpine AS build
WORKDIR /src
# No third-party dependencies, so the module files alone are the whole graph.
COPY go.mod ./
# Glob, not an enumeration. Naming main.go explicitly meant adding a second
# source file silently produced a container that would not compile -- caught
# only at build time, after the change had already been committed and tested
# locally where every file is present.
COPY *.go ./
# Static binary: the runtime image has no libc.
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/switch-portal .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/switch-portal /usr/local/bin/switch-portal
# distroless nonroot is uid 65532. The service reads only its projected
# service account token and an optional CA file, both world-readable.
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/switch-portal"]
