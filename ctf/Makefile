CXX := clang++
CXXFLAGS ?= -std=c++20 -O2
PLUGIN ?= ../build/obfuscation/libEnsia.so
LIBS = -ldl -lpthread

SRCS = src/main.cpp
HDRS = src/crypto_core.hpp src/zeroize.hpp src/obf_str.hpp

all: challenge_clean challenge_obf

challenge_clean: $(SRCS) $(HDRS)
	$(CXX) $(CXXFLAGS) $(SRCS) -o challenge_clean $(LIBS)

challenge_obf: $(SRCS) $(HDRS) $(PLUGIN)
	ENSIA_PRESET=max $(CXX) $(CXXFLAGS) -fpass-plugin=$(PLUGIN) $(SRCS) -o challenge_obf $(LIBS)

test: challenge_clean challenge_obf
	@echo "=== Testing Clean Challenge ==="
	python3 solution/solve.py ./challenge_clean
	@echo "=== Testing Obfuscated Challenge (Max Mode) ==="
	python3 solution/solve.py ./challenge_obf

clean:
	rm -f challenge_clean challenge_obf

.PHONY: all test clean
