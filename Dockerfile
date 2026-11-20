# One image, two Cloud Run services:
#   api      /app/server                                   (OAuth 2.1 server + policy/risk engine + console API)
#   gateway  /app/mcp-gateway -config config/mcp-upstreams.cloud.json   (MCP enforcement gateway)
# The gateway runs real upstream MCP servers as child processes, so the image also carries
# Node (official filesystem server) and uv/Python (official fetch server).

FROM golang:1.26-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/server ./cmd/server \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/mcp-gateway ./cmd/mcp-gateway \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/demo-bank-mcp ./cmd/demo-bank-mcp

FROM ghcr.io/astral-sh/uv:0.9.22 AS uv

FROM node:22-bookworm-slim
ENV UV_TOOL_DIR=/opt/uv/tools UV_TOOL_BIN_DIR=/usr/local/bin UV_PYTHON_INSTALL_DIR=/opt/uv/python \
    NODE_ENV=production NPM_CONFIG_UPDATE_NOTIFIER=false
COPY --from=uv /uv /uvx /usr/local/bin/
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/* \
 && npm install -g @modelcontextprotocol/server-filesystem@2.2.0 \
 && uv tool install mcp-server-fetch==2026.11.4 \
 && chmod -R a+rX /opt/uv \
 && useradd --create-home --uid 10001 app

WORKDIR /app
COPY --from=build /out/ /app/
COPY config ./config
COPY data/incidents.json data/competitors.json data/deals.json ./data/
COPY demo-data ./demo-data
RUN rm -f demo-data/bank_state.json && chown -R app:app /app
USER app
ENV PORT=8080
EXPOSE 8080
CMD ["/app/server"]
