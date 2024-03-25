VERSION 0.8
FROM golang:1.22
WORKDIR /vault-plugin-secrets-grafana-cloud

deps:
    COPY go.mod go.sum ./
    RUN go mod download
    SAVE ARTIFACT go.mod AS LOCAL go.mod
    SAVE ARTIFACT go.sum AS LOCAL go.sum

build:
    FROM +deps
    COPY *.go .
    COPY --dir ./cmd .
    RUN CGO_ENABLED=0 go build -o bin/vault-plugin-secrets-grafana-cloud cmd/grafana-cloud/main.go
    SAVE ARTIFACT bin/vault-plugin-secrets-grafana-cloud /grafana-cloud AS LOCAL bin/vault-plugin-secrets-grafana-cloud

test:
    FROM +deps
    COPY *.go .
    RUN --secret TEST_GRAFANA_CLOUD_TOKEN CGO_ENABLED=0 go test github.com/bloominlabs/vault-plugin-secrets-grafana-cloud

dev:
  BUILD +build
  LOCALLY
  RUN --secret GRAFANA_CLOUD_ACCESS_POLICY_ID --secret GRAFANA_CLOUD_TOKEN --secret GRAFANA_CLOUD_TOKEN_ID bash ./scripts/dev.sh

all:
  BUILD +build
  BUILD +test
