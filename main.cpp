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
	uint64_t temp = get_register_value(m_pid, reg::rip);
}

void debugger::set_pc(uint64_t pc) { //wrapper for program counter setting
	set_register_value(m_pid, reg::rip, pc);
}

//END HELPER FUNCTIONS

dwarf::line_table::iterator debugger::get_line_entry_from_pc(uint64_t pc) {
	for (auto &cu : m_dwarf.compilation_units()) { //loop through compilation units
		if (die_pc_range(cu.root()).contains(pc)) { //get compilation unit that contains program counter
			auto &lt = cu.get_line_table();
 
			auto it = lt.find_address(pc); //ask line table to get relevant entry of program counter
			if (it == lt.end()) {
				throw std::out_of_range{"Cannot find line entry"};
			}
			else {
				return it;
			}
		}
	}
	throw std::out_of_range{"Cannot find line entry"};
}

dwarf::die debugger::get_function_from_pc(uint64_t pc) { 
	for (auto &cu : m_dwarf.compilation_units()) { //for each compile unit
		if (die_pc_range(cu.root()).contains(pc)) { //if program counter between DW_AT_low_pc an DW_AT_high_pc
			for (const auto& die : cu.root()) { //for each function in compile unit
				if (die.tag == dwarf::DW_TAG::subprogram) { 
					if (die_pc_range(die).contains(pc)) { //if program counter between DW_AT_low_pc and DW_AT_high_pc
						return die; //return function information
					}
				}
			}
		}
	}
	throw std::out_of_range{"Cannot find function"};
}

siginfo_t debugger::get_signal_info() { //method to get information about last signal process was sent
	siginfo_t info; //siginfo_t is an obejct with process info
	ptrace(PTRACE_GETSIGINFO, m_pid, nullptr, &info);
	return info;
}

void debugger::single_step_instruction() {
	ptrace(PTRACE_SINGLESTEP, m_pid, nullptr, nullptr);
	wait_for_signal();
}

void debugger::single_step_instruction_with_breakpoint_check() {
	if (m_breakpoints.count(get_pc())) { //first check if this step will include a breakpoint
		step_over_breakpoint();	//if it does, we step over breakpoint - this includes disabling & re-enabling
	}							//the breakpoint
	else {
		single_step_instruction(); //otherwise, just make a step
	}
}

void debugger::handle_sigtrap(siginfo_t info) {
	switch (info.si_code) {
		case SI_KERNEL: //if breakpoint hit one of these will be set
		case TRAP_BRKPT:
		{
			set_pc(get_pc() - 1); //return program counter to where it should be
			std::cout << "Hit breakpoint at address 0x" << std::hex << get_pc() << std::endl;
			auto line_entry = get_line_entry_from_pc(get_pc());
			
			print_source(line_entry->file->path, line_entry->line);
			return;
		}
		//will be set if signal sent by single stepping
		case TRAP_TRACE:
			return;
		default:
			std::cout << "Unkown SIGTRAP code " << info.si_code << std::endl;
			return;
	}
}

void debugger::print_source(const std::string& file_name, unsigned line, unsigned n_lines_context) {
	std::ifstream file {file_name};
	
	//Work out a window around the desired line
	auto start_line = line <= n_lines_context ? 1 : line - n_lines_context;
	auto end_line = line + n_lines_context + (line < n_lines_context ? n_lines_context - line : 0) + 1;
	
	
	char c{};
	auto current_line = 1u;
	//skip lines until start_line
	while (current_line != start_line && file.get(c)) {
		if (c == '\n') {
			++current_line;
		}
	}
	
	//output cursor if we're at current line
	std::cout << (current_line == line ? "> " : " ");
	
	//write lines up until end_line
	while (current_line <= end_line && file.get(c)) {
		std::cout << c;
		if (c == '\n') {
			++current_line;
			//output cursor if at current line
			std::cout << (current_line == line ? "> " : " ");
		}
	}
	//write newline and make sure that the stream is flushed properly
	std::cout << std::endl;
}

void debugger::step_over_breakpoint() {
	if (m_breakpoints.count(get_pc())) { //if value at location key non-zero (overflow prevention)
		auto& bp = m_breakpoints[get_pc()];
		if (bp.is_enabled()) {			
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
	
	auto siginfo = get_signal_info();
	
	switch (siginfo.si_signo) { //si_signo is member of siginfo that details which signal was sent to process
		case SIGTRAP:
			handle_sigtrap(siginfo);
			break;
		case SIGSEGV: //si_code is siginfo member that gives more information about signal sent to process
			std::cout << "Segfault. Reason: " << siginfo.si_code << std::endl;
			break;
		default:
			std::cout << "Got signal " << strsignal(siginfo.si_signo) << std::endl;
	}
}

void debugger::dump_registers() {
	for (const auto& rd : g_register_descriptors) {
		std::cout << rd.name << " 0x"
				  << std::setfill('0') << std::setw(16) << std::hex
				  << get_register_value(m_pid, rd.r) << std::endl;
	}
}

void debugger::set_breakpoint_at_address(std::intptr_t addr) {
	//std::cout << addr << std::endl; //std::hex in output converts long back to hexadecimal
	std::cout << "Set breakpoint at address 0x" << std::hex << addr << std::endl; 
	//std::cout << addr << std::endl;
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

std::intptr_t debugger::offset_address(std::string& addr) {
	std::cout << m_pid << std::endl;
	
	std::string filepath = "/proc/";
	filepath += std::to_string(m_pid);
	filepath += "/maps";
	
	std::string load_address = "";
	std::ifstream load_address_file (filepath);
	std::getline(load_address_file, load_address, '-');
	
	int64_t loadTemp, instTemp;
	instTemp = std::stoul(addr, nullptr, 16); // turn the address strings into int64_t type
	loadTemp = std::stoul(load_address, nullptr, 16);
	std::cout << std::hex << loadTemp << " " << instTemp << " " << instTemp - loadTemp << std::endl;
	
	std::string temp = "";
	std::stringstream ss;
	ss << std::hex << instTemp + loadTemp;
	ss >> temp;
	instTemp = std::stoul(temp, nullptr, 16);
	std::cout << instTemp << std::endl;
	
	std::cout << load_address << std::endl;
	return instTemp;
}

uint64_t debugger::undo_offset_address(uint64_t pcval) {
	std::string filepath = "/proc/";
	filepath += std::to_string(m_pid);
	filepath += "/maps";
	
	std::cout << "Current PC value: " << pcval << std::endl;
	
	std::string load_address = "";
	std::ifstream load_address_file (filepath);
	std::getline(load_address_file, load_address, '-');
	
	int64_t loadTemp, pcTemp;
	loadTemp = std::stoul(load_address, nullptr, 16);
	
	std::string temp = "";
	std::stringstream ss;
	ss << std::hex << pcval - loadTemp;
	ss >> temp;
	pcTemp = std::stoul(temp, nullptr, 16);
	
	std::cout << "Old PC value: " << pcTemp << std::endl;
	
	return pcTemp;
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
		//std::string addr {args[1], 2}; //Assume user supplies correct address.. remove first 2 characters of string
		
		//std::cout << std::stol(addr, 0, 16) << std::endl;
		//set_breakpoint_at_address(std::stol(addr, 0, 16)); //read hexadecimal into long type
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
		std::string addr {args[2], 2}; //assume hex address
		if (is_prefix(args[1], "read")) {
			std::cout << std::hex << read_memory(std::stol(addr, 0, 16)) << std::endl;
		}
		else if (is_prefix(args[1], "write")) {
			std::string val {args[3], 2}; //assume hex
			write_memory(std::stol(addr, 0, 16), std::stol(val, 0, 16));
		}
	}
	else if (is_prefix(command, "stepi")) { //stepping command
		single_step_instruction_with_breakpoint_check();
		auto line_entry = get_line_entry_from_pc(get_pc()); //each time we step, print the corresponding
		print_source(line_entry->file->path, line_entry->line); //line of source code we step to
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