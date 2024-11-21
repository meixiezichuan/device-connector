.PHONY: generate-device generate-pod build-cli build-test run test stop bpftool clean clean-ebpf clean-linux
.DEFAULT_TARGET = run

# main
BIN_DIR=bin
RE_BIN_NAME=deviceproxy
PO_BIN_NAME=podproxy

CLANG := clang
CFLAGS := -g -O2 -Wall -Wextra $(CFLAGS)

generate-device: export BPF_CLANG := $(CLANG)
generate-device: export BPF_CFLAGS := $(CFLAGS)
generate-device:
	cd pkg/device_proxy && go generate -v ./...

generate-pod: export BPF_CLANG := $(CLANG)
generate-pod: export BPF_CFLAGS := $(CFLAGS)
generate-pod:
	cd pkg/pod_proxy && go generate -v ./...

build: generate-pod generate-device
	@echo -e "# bin/server build started"
	mkdir -p bin
	go build -o ${BIN_DIR}/${RE_BIN_NAME} deviceProxy/main.go
	go build -o ${BIN_DIR}/${PO_BIN_NAME} podProxy/main.go	

test-e2e: build
	@echo -e "\n# running e2e test"
	@./test/e2e.pre
	@./test/e2e.bats
	@./test/e2e.post

e2e: test-e2e clean

stop:
	@echo -e "\n# kill sk"
	@pkill ${BIN_NAME}

clean: stop
	@echo -e "# clean binaries"
	@rm ${BIN_DIR}/${BIN_NAME}
