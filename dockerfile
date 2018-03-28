FROM golang:latest as builder

WORKDIR /go/src/github.com/naveego/vault-jose-plugin

# install dep
RUN go get github.com/golang/dep/cmd/dep

#install ginkgo
RUN go get -u github.com/onsi/ginkgo/ginkgo 

# add Gopkg.toml and Gopkg.lock
ADD Gopkg.toml Gopkg.toml
ADD Gopkg.lock Gopkg.lock

# install packages
RUN dep ensure -v --vendor-only

ADD . .

#RUN go test -v ./...
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags "-s" -a -installsuffix cgo -o build/jose-plugin
RUN shasum -a 256 -p build/jose-plugin | cut -d ' ' -f 1 > "build/jose-plugin.sha"

## build the docker container with vault and the plugin mounted
FROM vault:latest

ENV VAULT_PORT 8200
ENV VAULT_TOKEN ""
ENV VAULT_ADDR "http://0.0.0.0:${VAULT_PORT}"
ENV VAULT_CLUSTER_ADDR ""
ENV VAULT_API_ADDR ""
#ENV VAULT_LOCAL_CONFIG '{ "plugin_directory": "/vault/plugins", "storage": { "file": { "path": "/vault/file" } } }'
ENV VAULT_DEV_ROOT_TOKEN_ID "root"
ENV VAULT_LOG_LEVEL "trace"

RUN apk --no-cache add ca-certificates
RUN mkdir -p /vault/plugins
RUN mkdir -p /vault/data

EXPOSE ${VAULT_PORT}

WORKDIR /vault/plugins
COPY --from=builder /go/src/github.com/naveego/vault-jose-plugin/build /vault/plugins
COPY --from=builder /go/src/github.com/naveego/vault-jose-plugin/build/config.hcl /vault/config/config.hcl

RUN chmod a+x *.sh
#RUN ./setup_vault.sh

ENTRYPOINT [ "/vault/plugins/start_vault.sh" ]

# mount point for a vault config
VOLUME [ "/vault/config" ]

CMD ["server", "-dev"]
