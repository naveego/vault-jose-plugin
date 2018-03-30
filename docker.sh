#!/bin/sh


docker build --tag vault-jose .
docker run --rm --name vault-jose -p 8200:8200 --cap-add IPC_LOCK vault-jose
