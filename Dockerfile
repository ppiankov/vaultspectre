FROM golang:1.25-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

ARG VERSION=dev
ARG COMMIT=none

RUN CGO_ENABLED=0 go build \
    -ldflags="-s -w -X github.com/ppiankov/vaultspectre/internal/commands.Version=${VERSION} -X github.com/ppiankov/vaultspectre/internal/commands.Commit=${COMMIT}" \
    -o /vaultspectre ./cmd/vaultspectre

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /vaultspectre /usr/local/bin/vaultspectre
ENTRYPOINT ["vaultspectre"]
