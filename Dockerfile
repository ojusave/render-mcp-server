FROM golang:1.26-alpine@sha256:28d89ee9cc0ff9fec75c82ca201e6bf7fdf9a679d4b7b24dfa04f2bb766bb468 AS build
ARG VERSION="dev"

# Set the working directory
WORKDIR /build

# Install git
RUN --mount=type=cache,target=/var/cache/apk \
    apk add git

# Build the MCP server
# go build automatically download required module dependencies to /go/pkg/mod
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=bind,target=. \
    CGO_ENABLED=0 go build -ldflags="-s -w -X cfg.version=${VERSION} " \
    -o /bin/render-mcp-server main.go

# Make a stage to run the app
FROM gcr.io/distroless/base-debian12@sha256:76b3162a31477bca4a245b836c624f4c4a1a3705e99b9003907d992bec2c4bca
# Set the working directory
WORKDIR /server
# Copy the binary from the build stage
COPY --from=build /bin/render-mcp-server .
# Set default config path (inside container)
ENV RENDER_CONFIG_PATH=/config/mcp-server.yaml
# Use ENTRYPOINT instead of CMD so that additional user-provided args are passed to the server
ENTRYPOINT ["./render-mcp-server"]
CMD []
