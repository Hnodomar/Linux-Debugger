#include "linenoise.h"

#include <vector>

#include <iostream>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fstream>
#include <sstream>
#include <stddef.h>

#include "debugger.hpp"
#include "registers.hpp"

using namespace minidbg;

//HELPER FUNCTIONS
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

uint64_t debugger::read_memory(uint64_t address) { //'hides' ptrace call to read memory address
	return ptrace(PTRACE_PEEKDATA, m_pid, address, nullptr);
}

void debugger::write_memory(uint64_t address, uint64_t value) { //'hides' ptrace call to write to memory address
	ptrace(PTRACE_POKEDATA, m_pid, address, value);
}

uint64_t debugger::get_pc() { //wrapper for program counter getting
	return get_register_value(m_pid, reg::rip);
}

void debugger::set_pc(uint64_t pc) { //wrapper for program counter setting
	set_register_value(m_pid, reg::rip, pc);
}

//END HELPER FUNCTIONS

void debugger::step_over_breakpoint() {
	// -1 because execution will go past the breakpoint
	auto possible_breakpoint_location = get_pc() - 1;
	if (m_breakpoints.count(possible_breakpoint_location)) { //if value at location key non-zero (overflow prevention)
		auto& bp = m_breakpoints[possible_breakpoint_location];
		if (bp.is_enabled()) {
			auto previous_instruction_address = possible_breakpoint_location;
			set_pc(previous_instruction_address); //put execution back to before the breakpoint
			
			bp.disable();	//disable breakpoint
			ptrace(PTRACE_SINGLESTEP, m_pid, nullptr, nullptr); //step over original instruction
			wait_for_signal();
			bp.enable(); //re-enable breakpoint
		}
	}
}

void debugger::wait_for_signal() {
	int wait_status;
	auto options = 0;
	waitpid(m_pid, &wait_status, options);
}

void debugger::dump_registers() {
	for (const auto& rd : g_register_descriptors) {
		std::cout << rd.name << " 0x"
				  << std::setfill('0') << std::setw(16) << std::hex
				  << get_register_value(m_pid, rd.r) << std::endl;
	}
}

void debugger::set_breakpoint_at_address(std::intptr_t addr) {
	std::cout << "Set breakpoint at address 0x" << std::hex << addr << std::endl;
	breakpoint bp {m_pid, addr};
	bp.enable();
	m_breakpoints[addr] = bp;
}

void debugger::continue_execution() {
	step_over_breakpoint();
	ptrace(PTRACE_CONT, m_pid, nullptr, nullptr);
	wait_for_signal();
}

void debugger::run() {
    int wait_status;
    auto options = 0;
    waitpid(m_pid, &wait_status, options); //wait until child process finished launching
	//when traced process launched, will be sent SIGTRAP signal (trace / breakpoint trap)
	//wait until this signal is sent with waitpid
	
    char* line = nullptr;
    while((line = linenoise("minidbg> ")) != nullptr) { //Keep getting input from linenoise until we hit EOF
        handle_command(line);
        linenoiseHistoryAdd(line);
        linenoiseFree(line);
    }
}

void debugger::handle_command(const std::string& line) {
	auto args = split(line, ' ');
	auto command = args[0];
	
	if (is_prefix(command, "continue")) {
		continue_execution();
	}
	else if (is_prefix(command, "break")) {
		std::string addr {args[1], 2}; //Assume user supplies correct address.. remove first 2 characters of string
		set_breakpoint_at_address(std::stol(addr, 0, 16)); //read hexadecimal into long type
	}
	else if (is_prefix(command, "register")) {
		if (is_prefix(args[1], "dump")) {
			dump_registers();
		}
		else if (is_prefix(args[1], "read")) {
			std::cout << get_register_value(m_pid, get_register_from_name(args[2])) << std::endl;
		}
		else if (is_prefix(args[1], "write")) {
			std::string val {args[3], 2}; //assume hex address
			set_register_value(m_pid, get_register_from_name(args[2]), std::stol(val, 0, 16));
		}
	}
	else if (is_prefix(command, "memory")) {
		std:string addr {args[2], 2}; //assume hex address
		if (is_prefix(args[1], "read")) {
			std::cout << std::hex << read_memory(std::stol(addr, 0, 16)) << std::endl;
		}
		else if (is_prefix(args[1], "write")) {
			std::string val {args[3], 2}; //assume hex
			write_memory(std::stol(addr, 0, 16), std::stol(val, 0, 16));
		}
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