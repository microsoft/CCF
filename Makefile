BUILD=build
INSTALL_PREFIX=$(BUILD)/myopt
GLOBAL_INSTALL_PREFIX=/opt/ccf

CPP_INCLUDES=$(wildcard include/ccf/**/*.cpp)
H_INCLUDES=$(wildcard include/ccf/**/*.h)

.PHONY: build-virtual
build-virtual:
	mkdir -p $(BUILD)
	cd $(BUILD) && cmake -GNinja -DCOMPILE_TARGET=virtual -DCMAKE_INSTALL_PREFIX=$(abspath $(INSTALL_PREFIX))_virtual -DVERBOSE_LOGGING=OFF -DUNSAFE_VERSION=OFF ..
	cd $(BUILD) && ninja

.PHONY: build-virtual-verbose
build-virtual-verbose:
	mkdir -p $(BUILD)
	cd $(BUILD) && cmake -GNinja -DCOMPILE_TARGET=virtual -DCMAKE_INSTALL_PREFIX=$(abspath $(INSTALL_PREFIX))_virtual -DVERBOSE_LOGGING=ON -DUNSAFE_VERSION=ON ..
	cd $(BUILD) && ninja

.PHONY: build-virtual-global
build-virtual-global:
	mkdir -p $(BUILD)
	cd $(BUILD) && cmake -GNinja -DCOMPILE_TARGET=virtual -DCMAKE_INSTALL_PREFIX=$(GLOBAL_INSTALL_PREFIX)_virtual -DVERBOSE_LOGGING=OFF -DUNSAFE_VERSION=OFF ..
	cd $(BUILD) && ninja

.PHONY: build-sgx-global
build-sgx-global:
	mkdir -p $(BUILD)
	cd $(BUILD) && cmake -GNinja -DCOMPILE_TARGET=sgx -DCMAKE_INSTALL_PREFIX=$(GLOBAL_INSTALL_PREFIX)_sgx -DVERBOSE_LOGGING=OFF -DUNSAFE_VERSION=OFF ..
	cd $(BUILD) && ninja

.PHONY: build-snp-global
build-snp-global:
	mkdir -p $(BUILD)
	cd $(BUILD) && cmake -GNinja -DCOMPILE_TARGET=snp -DCMAKE_INSTALL_PREFIX=$(GLOBAL_INSTALL_PREFIX)_snp -DVERBOSE_LOGGING=OFF -DUNSAFE_VERSION=OFF ..
	cd $(BUILD) && ninja

.PHONY: build-virtual-global-verbose
build-virtual-global-verbose:
	mkdir -p $(BUILD)
	cd $(BUILD) && cmake -GNinja -DCOMPILE_TARGET=virtual -DCMAKE_INSTALL_PREFIX=$(GLOBAL_INSTALL_PREFIX)_virtual -DVERBOSE_LOGGING=ON -DUNSAFE_VERSION=ON ..
	cd $(BUILD) && ninja

.PHONY: install-virtual
install-virtual: build-virtual
	cd $(BUILD) && ninja install

.PHONY: install-virtual-global
install-virtual-global: build-virtual-global
	cd $(BUILD) && sudo ninja install

.PHONY: install-sgx-global
install-sgx-global: build-sgx-global
	cd $(BUILD) && sudo ninja install

.PHONY: install-virtual-global-verbose
install-virtual-global-verbose: build-virtual-global-verbose
	cd $(BUILD) && sudo ninja install

.PHONY: run-sandbox
run-sandbox: build-virtual
	cd $(BUILD) && ../tests/sandbox/sandbox.sh

.PHONY: run-sandbox-cpp-logging
run-sandbox-cpp-logging: build-virtual
	cd $(BUILD) && ../tests/sandbox/sandbox.sh -p samples/apps/logging/liblogging

.PHONY: test-virtual
test-virtual: build-virtual
	cd $(BUILD) && ./tests.sh

.PHONY: clean
clean:
	rm -rf $(INSTALL_PREFIX) $(BUILD) workspace

cpplint: $(CPP_INCLUDES) $(H_INCLUDES)
	cpplint --filter=-whitespace/braces,-whitespace/indent,-whitespace/comments,-whitespace/newline,-build/include_order,-build/include_subdir,-runtime/references,-runtime/indentation_namespace $(CPP_INCLUDES) $(H_INCLUDES)
