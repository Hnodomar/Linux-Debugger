#include "linenoise.h"

#include <string>

#include <vector>
#include <iostream>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fstream>
#include <sstream>
#include <stddef.h>
#include <iomanip>
#include <fcntl.h>

#include "debugger.hpp"

using namespace minidbg;

std::vector<std::string> split(const std::string &s, char delimiter) {
	std::vector<std::string> out{};
	std::stringstream ss {s};
	std::string item;
	
	while (std::getline(ss, item, delimiter))
			out.push_back(item);
	
	return out;
}

bool is_prefix(const std::string& s, const std::string& of) {
	if (s.size() > of.size()) return false;
	return std::equal(s.begin(), s.end(), of.begin());
}

//END HELPER FUNCTIONS

void debugger::set_breakpoint_at_address(std::intptr_t addr) {
	std::cout << "Set breakpoint at address 0x" << std::hex << addr << std::endl; 
	breakpoint bp {m_pid, addr};
	bp.enable();
	m_breakpoints[addr] = bp;
}

void debugger::continue_execution() {
    ptrace(PTRACE_CONT, m_pid, nullptr, nullptr);

    int wait_status;
    auto options = 0;
    waitpid(m_pid, &wait_status, options);
}

void debugger::run() {
    int wait_status;
    auto options = 0;
    waitpid(m_pid, &wait_status, options); //wait until child process finished launching
	//when traced process launched, will be sent SIGTRAP signal (trace / breakpoint trap)
	//wait until this signal is sent with waitpid
	
    char* line = nullptr;
    while((line = linenoise("minidbg> ")) != nullptr) { //Keep getting input from linenoise until we hit EOF
        handle_command(line); //handle command and then return, waiting for the next command
        linenoiseHistoryAdd(line);
        linenoiseFree(line);
    }
}

std::intptr_t debugger::offset_address(std::string& addr) {
	//std::cout << m_pid << std::endl;
	
	std::string filepath = "/proc/";
	filepath += std::to_string(m_pid);
	filepath += "/maps";
	
	std::string load_address = "";
	std::ifstream load_address_file (filepath);
	std::getline(load_address_file, load_address, '-');
	
	int64_t loadTemp, instTemp;
	instTemp = std::stoul(addr, nullptr, 16); // turn the address strings into int64_t type
	loadTemp = std::stoul(load_address, nullptr, 16);
	//std::cout << std::hex << loadTemp << " " << instTemp << " " << instTemp - loadTemp << std::endl;
	
	std::string temp = "";
	std::stringstream ss;
	ss << std::hex << instTemp + loadTemp;
	ss >> temp;
	instTemp = std::stoul(temp, nullptr, 16);
	//std::cout << instTemp << std::endl;
	
	//std::cout << load_address << std::endl;
	return instTemp;
}

void debugger::handle_command(const std::string& line) {
	auto args = split(line, ' ');
	auto command = args[0];
	
	if (is_prefix(command, "continue")) {
		continue_execution();
	}
	else if (is_prefix(command, "break")) {
		std::string addr{args[1]};
		std::intptr_t correct_address = offset_address(addr);
		set_breakpoint_at_address(correct_address);
	}
	else {
		std::cerr << "Unknown command\n";
	}
}


// fork/exec pattern

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Program to debug not specified";
        return -1;
    }
    auto prog = argv[1];
    auto pid = fork(); //Create new process (called a child process)
    if (pid == 0) { //fork returns 0 to newly created child process
    //child goes here - execute debugee
        ptrace(PTRACE_TRACEME, 0, nullptr, nullptr); //allow parent to trace child
        execl(prog, prog, nullptr); //analogous: ./prog prog i.e: ./fullPath processName
    }
    else if (pid >= 1) { //positive value returned by fork will be child process ID
    //parent goes here - execute debugger
        debugger dbg{prog, pid};
        dbg.run();
    }
}