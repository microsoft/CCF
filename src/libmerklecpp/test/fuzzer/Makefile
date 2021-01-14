all: fuzzer

fuzzer: fuzzer.cpp
	clang++-8 -g -O1 -fsanitize=fuzzer,address -fno-omit-frame-pointer -fprofile-instr-generate -fcoverage-mapping  $< -o $@

clean:
	rm -rf fuzzer

show:
	llvm-profdata merge -sparse *.profraw -o default.profdata
	llvm-cov show fuzzer -instr-profile=default.profdata