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
#include "registers.hpp"

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

uint64_t debugger::read_memory(uint64_t address) {
	return ptrace(PTRACE_PEEKDATA, m_pid, address, nullptr);
}

void debugger::write_memory(uint64_t address, uint64_t value) {
	ptrace(PTRACE_POKEDATA, m_pid, address, value);
}

uint64_t debugger::get_pc() {
	return get_register_value(m_pid, reg::rip);
}

void debugger::set_pc(uint64_t pc) {
	set_register_value(m_pid, reg::rip, pc);
}

//END HELPER FUNCTIONS

void debugger::step_over_breakpoint() { 
	auto possible_breakpoint_location = get_pc() - 1;
	if (m_breakpoints.count(possible_breakpoint_location)) { //check to see if there is breakpoint
		auto& bp = m_breakpoints[possible_breakpoint_location];
		if (bp.is_enabled()) { //if enabled
			auto previous_instruction_address = possible_breakpoint_location;
			set_pc(previous_instruction_address); //put execution back to before the breakpoint
			
			bp.disable(); //disable
			ptrace(PTRACE_SINGLESTEP, m_pid, nullptr, nullptr); //step over breakpoint
			wait_for_signal(); //wait for ptrace to step
			bp.enable(); //re-enable
		}
	}
}

void debugger::dump_registers() {
	for (const auto& rd : g_register_descriptors) {
		std::cout << rd.name << " 0x" << std::setfill('0') << std::setw(16)
			<< std::hex << get_register_value(m_pid, rd.r) << std::endl;
	}
}

void debugger::set_breakpoint_at_address(std::intptr_t addr) {
	std::cout << "Set breakpoint at address 0x" << std::hex << addr << std::endl; 
	breakpoint bp {m_pid, addr};
	bp.enable();
	m_breakpoints[addr] = bp;
}

void debugger::wait_for_signal() {
	int wait_status;
	auto options = 0;
	waitpid(m_pid, &wait_status, options);
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
	else if (is_prefix(command, "register")) {
		if (is_prefix(args[1], "dump")) {
			dump_registers();
		}
		else if (is_prefix(args[1], "read")) {
			std::cout << get_register_value(m_pid, get_register_from_name(args[2])) << std::endl;
		}
		else if (is_prefix(args[1], "write")) {
			std::string val {args[3]};
			auto correct_value = offset_address(val);
			set_register_value(m_pid, get_register_from_name(args[2]), correct_value);
		}
	}
	else if (is_prefix(command, "memory")) {
		std::string addr {args[2], 2};
		if (is_prefix(args[1], "read")) {
			std::cout << std::hex << read_memory(std::stol(addr, 0, 16)) << std::endl;
		}
		else if (is_prefix(args[1], "write")) {
			std::string val {args[3], 2};
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