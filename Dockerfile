# syntax=docker/dockerfile:1
FROM golang:1.25-alpine AS build

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=none
ARG BUILD_DATE=unknown

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} go build \
    -trimpath \
    -ldflags="-s -w -X github.com/gokulapap/wappalyzer-cli/internal/buildinfo.Version=${VERSION} -X github.com/gokulapap/wappalyzer-cli/internal/buildinfo.Commit=${COMMIT} -X github.com/gokulapap/wappalyzer-cli/internal/buildinfo.Date=${BUILD_DATE}" \
    -o /out/wappy ./cmd/wappy

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/wappy /usr/local/bin/wappy
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/wappy"]
