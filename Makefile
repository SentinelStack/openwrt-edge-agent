IMAGE_NAME ?= openwrt-c-toolchain:23.05.3
ROUTER ?= root@192.168.1.1
BIN ?= openwrt-agent
SRCS := src/main.c src/packet_capture.c src/packet_parser.c src/traffic_stats.c \
	src/anomaly_detector.c src/flow_table.c src/dns_window.c src/client_roster.c src/packet_window.c src/fx_ring.c src/uploader.c \
	src/iso_time.c src/http_client.c src/backend_client.c src/rules_client.c src/logger.c

.PHONY: docker-build build check deploy run run-tcp run-udp clean

docker-build:
	docker build --platform linux/amd64 -t $(IMAGE_NAME) -f Dockerfile .

MBEDTLS ?= /opt/mbedtls

build:
	docker run --rm --platform linux/amd64 -v "$(PWD):/work" -w /work $(IMAGE_NAME) \
		arm-openwrt-linux-muslgnueabi-gcc -O2 -Wall -Wextra \
		-I$(MBEDTLS)/include -o $(BIN) $(SRCS) \
		-L$(MBEDTLS)/lib -lmbedtls -lmbedx509 -lmbedcrypto -lpthread

check:
	file $(BIN)

deploy:
	ROUTER=$(ROUTER) ./scripts/deploy.sh

run:
	ROUTER=$(ROUTER) ./scripts/run.sh

run-tcp:
	ROUTER=$(ROUTER) ./scripts/run.sh --tcp

run-udp:
	ROUTER=$(ROUTER) ./scripts/run.sh --udp

clean:
	rm -f $(BIN) *.o
