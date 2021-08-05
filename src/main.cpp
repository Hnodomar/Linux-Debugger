#include <string>
#include <iostream>

#include "debugger.hpp"

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Program to debug not specified";
        return -1;
    }
    auto prog = argv[1];
    auto pid = fork();
    if (pid == 0) {
        ptrace(PTRACE_TRACEME, 0, nullptr, nullptr); //allow parent to trace child
        execl(prog, prog, nullptr);
    }
    else if (pid >= 1) {
        minidbg::debugger dbg{prog, pid};
        dbg.run();
    }
}