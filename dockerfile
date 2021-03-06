FROM golang:1.11 as builder

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

RUN go test -v ./...
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags "-s" -a -installsuffix cgo -o build/jose-plugin
RUN shasum -a 256 -p build/jose-plugin | cut -d ' ' -f 1 > "build/jose-plugin.sha"

## build the docker container with vault and the plugin mounted
FROM vault:0.11.1

ENV VAULT_PORT 8200
ENV VAULT_TOKEN ""
ENV VAULT_ADDR "http://0.0.0.0:${VAULT_PORT}"
ENV VAULT_CLUSTER_ADDR ""
ENV VAULT_API_ADDR ""
ENV VAULT_LOCAL_CONFIG '{ "plugin_directory": "/vault/plugins" }'
ENV VAULT_DEV_ROOT_TOKEN_ID "root"
ENV VAULT_LOG_LEVEL "trace"

RUN mkdir -p /vault/plugins
RUN mkdir -p /vault/data
RUN mkdir /app 

EXPOSE ${VAULT_PORT}

WORKDIR /vault/plugins
COPY --from=builder /go/src/github.com/naveego/vault-jose-plugin/build /vault/plugins


# When using this in -dev mode, Vault will load all plugins in the plugins folder
# having the test files there was an error
ADD ./test /app/
RUN chmod a+x /app/*.sh

ENTRYPOINT [ "/app/start_vault.sh" ]

# mount point for a vault config
VOLUME [ "/vault/config" ]

CMD ["server", "-dev"]
