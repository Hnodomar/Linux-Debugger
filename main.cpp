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

//START HELPER FUNCTIONS
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

bool is_suffix(const std::string& s, const std::string& of) {
    if (s.size() > of.size()) return false;
    auto diff = of.size() - s.size();
    return std::equal(s.begin(), s.end(), of.begin() + diff);
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

void debugger::dump_registers() {
	for (const auto& rd : g_register_descriptors) {
		std::cout << rd.name << " 0x" << std::setfill('0') << std::setw(16)
			<< std::hex << get_register_value(m_pid, rd.r) << std::endl;
	}
}

void debugger::remove_breakpoint(std::intptr_t addr) {
	if (m_breakpoints.at(addr).is_enabled()) {
		m_breakpoints.at(addr).disable();
	}
	m_breakpoints.erase(addr);
}

//END HELPER FUNCTIONS
//DWARF SECTION START
uint64_t debugger::get_relative_pc(uint64_t Abspc) {
	std::cout << "abs pc: " << std::hex << Abspc << std::endl;
	
	std::string filepath = "/proc/";
	filepath += std::to_string(m_pid);
	filepath += "/maps";
	
	std::string load_address = "";
	std::ifstream load_address_file (filepath);
	std::getline(load_address_file, load_address, '-');
	
	int64_t loadTemp = std::stoul(load_address, nullptr, 16);

	std::string temp = "";
	std::stringstream ss;
	ss << std::hex << Abspc - loadTemp;
	ss >> temp;

	std::cout << "relative pc: " << temp << std::endl;
	return std::stoul(temp, nullptr, 16);
}

uint64_t debugger::get_abs_address(uint64_t addr) {
	std::string filepath = "/proc/";
	filepath += std::to_string(m_pid);
	filepath += "/maps";
	
	std::string load_address = "";
	std::ifstream load_address_file (filepath);
	std::getline(load_address_file, load_address, '-');
	
	int64_t loadTemp = std::stoul(load_address, nullptr, 16);

	std::string temp = "";
	std::stringstream ss;
	ss << std::hex << addr + loadTemp;
	ss >> temp;
	
	return std::stoul(temp, nullptr, 16);
}

dwarf::line_table::iterator debugger::get_line_entry_from_pc(uint64_t pc) {
	uint64_t relativepc = get_relative_pc(pc);
    for (auto &cu : m_dwarf.compilation_units()) {
        if (die_pc_range(cu.root()).contains(relativepc)) {
			std::cout << "here";
            auto &lt = cu.get_line_table();
            auto it = lt.find_address(relativepc);
            if (it == lt.end()) {
                throw std::out_of_range{"Cannot find line entry"};
            }
            else {
                return it;
            }
        }
    }
	std::cout << "here" << std::endl;
    throw std::out_of_range{"Cannot find line entry"};
}

dwarf::line_table::iterator debugger::get_line_entry_from_rel_pc(uint64_t pc) {
    for (auto &cu : m_dwarf.compilation_units()) {
        if (die_pc_range(cu.root()).contains(pc)) {
			std::cout << "here";
            auto &lt = cu.get_line_table();
            auto it = lt.find_address(pc);
            if (it == lt.end()) {
                throw std::out_of_range{"Cannot find line entry"};
            }
            else {
                return it;
            }
        }
    }
	std::cout << "here" << std::endl;
    throw std::out_of_range{"Cannot find line entry"};
}

dwarf::die debugger::get_function_from_pc(uint64_t pc) {
	uint64_t relativepc = get_relative_pc(pc);
    for (auto &cu : m_dwarf.compilation_units()) {
        if (die_pc_range(cu.root()).contains(relativepc)) {
            for (const auto& die : cu.root()) {
                if (die.tag == dwarf::DW_TAG::subprogram) {
                    if (die_pc_range(die).contains(relativepc)) {
                        return die;
                    }
                }
            }
        }
    }

    throw std::out_of_range{"Cannot find function"};
}

//DWARF SECTION END

symbol_type to_symbol_type(elf::stt sym) {
	switch (sym) { //need to map between symbol type returned by libelfin and enum class
		case elf::stt::notype: return symbol_type::notype;
		case elf::stt::object: return symbol_type::object;
		case elf::stt::func: return symbol_type::func;
		case elf::stt::section: return symbol_type::section;
		case elf::stt::file: return symbol_type::file;
		default: return symbol_type::notype;
	}
};

std::vector<symbol> debugger::lookup_symbol(const std::string& name) {
	std::vector<symbol> syms;
	for (auto &sec : m_elf.sections()) {
		if (sec.get_hdr().type != elf::sht::symtab && sec.get_hdr().type != elf::sht::dynsym) {
			continue;
		}
		for (auto sym : sec.as_symtab()) {
			if (sym.get_name() == name) {
				auto &d = sym.get_data();
				syms.push_back(symbol{to_symbol_type(d.type()), sym.get_name(), d.value});
			} //get all symbols and push them into syms vector
		}
	}
	return syms;
}

void debugger::set_breakpoint_at_source_line(const std::string& file, unsigned line) {
	for (const auto& cu : m_dwarf.compilation_units()) {
		if (is_suffix(file, at_name(cu.root()))) { //get compilation unit whose name corresponds to given file
			const auto& lt = cu.get_line_table();
			for (const auto& entry : lt) { 
				if (entry.is_stmt && entry.line == line) { //look for line corresponding to the desired line
					auto addr = get_abs_address(entry.address);
					set_breakpoint_at_address(addr); //set breakpoint at line address
					return;
				}
			}
		}
	}
}

void debugger::set_breakpoint_at_function(const std::string& name) {
	for (const auto& cu : m_dwarf.compilation_units()) { //loop through compilation units
		for (const auto& die : cu.root()) {
			if (die.has(dwarf::DW_AT::name) && at_name(die) == name) { //match against DW_AT_NAME
				auto low_pc = at_low_pc(die); //set breakpoint to start address of function
				auto entry = get_line_entry_from_rel_pc(low_pc);
				++entry; //get first line of user code instead of prologue
				set_breakpoint_at_address(entry->address);
			}
		}
	}
}

void debugger::step_over() { //set a breakpoint at the next source line
	//one problem: it's not that simple..
	//we could be in a loop, or a conditional construct
	//so.. it's not that simple!
	//SOLUTION: set a breakpoint at every line in the current function (not a great solution.. but still a solution)
	auto func = get_function_from_pc(get_pc());
	auto func_entry = at_low_pc(func); //come back to this - could be relative address
	auto func_end = at_high_pc(func); //get low and high PC values for given function DIE
	//std::cout << "func_entry: " << func_entry << " func_end: " << func_end << std::endl;
	
	auto line = get_line_entry_from_rel_pc(func_entry);
	auto start_line = get_line_entry_from_pc(get_pc());
	
	std::vector<std::intptr_t> to_delete{}; //must delete all breakpoints after we're done... store them here
	
	while (line->address < func_end) { //loop over line table entries until one is hit outside range of function
		if (line->address != start_line->address && !m_breakpoints.count(line->address)) { 
			set_breakpoint_at_address(line->address); //make sure each line is a line we're not currently on
			to_delete.push_back(line->address);		  //and that there isn't already a breakpoint set there
		}
		++line;
	}
	
	auto frame_pointer = get_register_value(m_pid, reg::rbp);
	
	auto return_address = read_memory(frame_pointer+8);
	if (!m_breakpoints.count(return_address)) { //if there isn't a breakpoint
		set_breakpoint_at_address(return_address);
		to_delete.push_back(return_address);
	}
	
	continue_execution();
	
	for (auto addr : to_delete) {
		remove_breakpoint(addr);
	}
}

void debugger::step_in() {
	auto line = get_line_entry_from_pc(get_pc())->line; //get the line of current instruction
	
	while (get_line_entry_from_pc(get_pc())->line == line) { //while the instructions refer to the same line we're
		single_step_instruction_with_breakpoint_check();	 //on, just keep stepping through instructions
	}														 //until we get to one on a different line
	
	auto line_entry = get_line_entry_from_pc(get_pc()); //the new line of instruction
	print_source(line_entry->file->path, line_entry->line); //print the new line we're on
}

void debugger::step_out() {
    auto frame_pointer = get_register_value(m_pid, reg::rbp);
    auto return_address = read_memory(frame_pointer+8);

    bool should_remove_breakpoint = false;
    if (!m_breakpoints.count(return_address)) {
        set_breakpoint_at_address(return_address);
        should_remove_breakpoint = true;
    }

    continue_execution();

    if (should_remove_breakpoint) {
        remove_breakpoint(return_address);
    }
}

void debugger::single_step_instruction() {
	ptrace(PTRACE_SINGLESTEP, m_pid, nullptr, nullptr);
	wait_for_signal();
}

void debugger::single_step_instruction_with_breakpoint_check() {
	//firstly check as to whether or not we need to disable and re-enable a breakpoint
	if (m_breakpoints.count(get_pc())) {
		step_over_breakpoint(); //this function already includes a ptrace SINGLE_STEP call
	}
	else {
		single_step_instruction();
	}
}

void debugger::print_source(const std::string& file_name, unsigned line, unsigned n_lines_context) {
    std::ifstream file {file_name};

    //Work out a window around the desired line
    auto start_line = line <= n_lines_context ? 1 : line - n_lines_context;
    auto end_line = line + n_lines_context + (line < n_lines_context ? n_lines_context - line : 0) + 1;

    char c{};
    auto current_line = 1u;
    //Skip lines up until start_line
    while (current_line != start_line && file.get(c)) {
        if (c == '\n') {
            ++current_line;
        }
    }

    //Output cursor if we're at the current line
    std::cout << (current_line==line ? "> " : "  ");

    //Write lines up until end_line
    while (current_line <= end_line && file.get(c)) {
        std::cout << c;
        if (c == '\n') {
            ++current_line;
            //Output cursor if we're at the current line
            std::cout << (current_line==line ? "> " : "  ");
        }
    }

    //Write newline and make sure that the stream is flushed properly
    std::cout << std::endl;
}

void debugger::step_over_breakpoint() {
    if (m_breakpoints.count(get_pc())) {
        auto& bp = m_breakpoints[get_pc()];
        if (bp.is_enabled()) {
            bp.disable();
            ptrace(PTRACE_SINGLESTEP, m_pid, nullptr, nullptr);
            wait_for_signal();
            bp.enable();
        }
    }
}

void debugger::set_breakpoint_at_address(std::intptr_t addr) {
	std::cout << "Set breakpoint at address 0x" << std::hex << addr << std::endl; 
	breakpoint bp {m_pid, addr};
	bp.enable();
	m_breakpoints[addr] = bp;
}

void debugger::handle_sigtrap(siginfo_t info) {
    switch (info.si_code) {
    //one of these will be set if a breakpoint was hit
    case SI_KERNEL:
    case TRAP_BRKPT:
    {
        set_pc(get_pc()-1); //put the pc back where it should be
        std::cout << "Hit breakpoint at address 0x" << std::hex << get_pc() << std::endl;
        auto line_entry = get_line_entry_from_pc(get_pc()); //display source line of our breakpoint
        print_source(line_entry->file->path, line_entry->line);
        return;
    }
    //this will be set if the signal was sent by single stepping
    case TRAP_TRACE:
        return;
    default:
        std::cout << "Unknown SIGTRAP code " << info.si_code << std::endl;
        return;
    }
}

void debugger::wait_for_signal() {
	int wait_status;
    auto options = 0;
    waitpid(m_pid, &wait_status, options);
	//when waiting for signal, when we get a signal, handle signal!
    auto siginfo = get_signal_info();

    switch (siginfo.si_signo) { //switch for different kinds of signals our child process gets sent
    case SIGTRAP:
        handle_sigtrap(siginfo);
        break;
    case SIGSEGV:
        std::cout << "Yay, segfault. Reason: " << siginfo.si_code << std::endl;
        break;
    default:
        std::cout << "Got signal " << strsignal(siginfo.si_signo) << std::endl;
    }
}

siginfo_t debugger::get_signal_info() { //wait_for_signal helper
    siginfo_t info;
    ptrace(PTRACE_GETSIGINFO, m_pid, nullptr, &info); //signal information
    return info;
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
	//std::cout << std::hex << 0x000005fa + loadTemp << std::endl;
	
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
		if (args[1][0] == '0' && args[1][1] == 'x') {
			std::string addr{args[1]};
			std::intptr_t correct_address = offset_address(addr);
			set_breakpoint_at_address(correct_address);
		}
		else if (args[1].find(':') != std::string::npos) {
			auto file_and_line = split(args[1], ':');
			set_breakpoint_at_source_line(file_and_line[0], std::stoi(file_and_line[1]));
		}
		else {
			set_breakpoint_at_function(args[1]);
		}
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
	else if (is_prefix(command, "stepi")) {
		single_step_instruction_with_breakpoint_check();
		auto line_entry = get_line_entry_from_pc(get_pc()); //want to print immediate source code each time we step
		print_source(line_entry->file->path, line_entry->line);
	}
	else if (is_prefix(command, "step")) {
		step_in();
	}
	else if (is_prefix(command, "next")) {
		step_over();
	}
	else if (is_prefix(command, "finish")) {
		step_out();
	}
	else if (is_prefix(command, "symbol")) {
		auto syms = lookup_symbol(args[1]);
		for (auto&& s : syms) {
			std::cout << s.name << ' ' << to_string(s.type) << " 0x" << std::hex << s.addr << std::endl;
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