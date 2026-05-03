IMAGE_NAME ?= openwrt-c-toolchain:23.05.3
ROUTER ?= root@192.168.1.1
BIN ?= net_filter
SRC ?= src/net_filter.c

.PHONY: docker-build build check deploy run-tcp run-udp clean

docker-build:
	docker build --platform linux/amd64 -t $(IMAGE_NAME) -f Dockerfile .

build:
	docker run --rm --platform linux/amd64 -v "$(PWD):/work" -w /work $(IMAGE_NAME) \
		arm-openwrt-linux-muslgnueabi-gcc -O2 -Wall -Wextra -o $(BIN) $(SRC)

check:
	file $(BIN)

deploy:
	ROUTER=$(ROUTER) ./scripts/deploy.sh

run-tcp:
	ROUTER=$(ROUTER) ./scripts/run.sh tcp

run-udp:
	ROUTER=$(ROUTER) ./scripts/run.sh udp

clean:
	rm -f $(BIN) *.o
