#!/bin/sh

# This runs a few commands to make sure we're able to build the plugin, install it, and communicate with it through the cli

docker-compose down
docker-compose up --build -d
./build-install.sh
./cli.sh

docker-compose down