#include "linenoise.h"

#include <vector>
#include <string>
#include <utility>
#include <iostream>
#include <linux/types.h>
#include <sys/ptrace.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <stddef.h>
#include <unordered_map>

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
//END HELPER FUNCTIONS
class breakpoint {
public:
	breakpoint() = default;
    breakpoint(pid_t pid, std::intptr_t addr)
        : m_pid{pid}, m_addr{addr}, m_enabled{false}, m_saved_data{}
    {}

    void enable();
    void disable();

    auto is_enabled() const -> bool { return m_enabled; }
    auto get_address() const -> std::intptr_t { return m_addr; }

private:
    pid_t m_pid;
    std::intptr_t m_addr;
    bool m_enabled;
    uint8_t m_saved_data; //data which used to be at the breakpoint address
};

void breakpoint::enable() { //breakpoint member function to set breakpoint trap at desired address
	auto data = ptrace(PTRACE_PEEKDATA, m_pid, m_addr, nullptr); //PTRACE_PEEKDATA: ptrace request to read memory of traced process
	m_saved_data = static_cast<uint8_t>(data & 0xff); //save the bottom byte of original data at breakpt address
	uint64_t int3 = 0xcc; //trap: breakpoint instruction
	uint64_t data_with_int3 = ((data & ~0xff) | int3); //bottom byte send to 0xcc - breakpoint instruction
	ptrace(PTRACE_POKEDATA, m_pid, m_addr, data_with_int3); //PTRACE_POKEDATA: ptrace request to write to memory
	m_enabled = true;
}

void breakpoint::disable() { //ptrace memory requests operate on whole words instead of bytes
	auto data = ptrace(PTRACE_PEEKDATA, m_pid, m_addr, nullptr); //so we need to read the word
	auto restored_data = ((data & ~0xff) | m_saved_data);		 //at the location and then
	ptrace(PTRACE_POKEDATA, m_pid, m_addr, restored_data);	     //overwrite the low byte with original data
	m_enabled = false;
}

class debugger { //To interact with child process
    public:
        debugger (std::string prog_name, pid_t pid) //constructor to initialise m_prog_name & m_pid
            : m_prog_name{std::move(prog_name)}, m_pid{pid} 
		{}
        
        void run();
		void set_breakpoint_at_address(std::intptr_t addr);
		
	private:
		void continue_execution();
		void handle_command(const std::string&);
		std::unordered_map<std::intptr_t,breakpoint> m_breakpoints;
        std::string m_prog_name;
        pid_t m_pid;
};

void debugger::set_breakpoint_at_address(std::intptr_t addr) {
	std::cout << "Set breakpoint at address 0x" << std::hex << addr << std::endl;
	breakpoint bp{m_pid, addr};
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
		set_breakpoint_at_address(std::stol("addr", 0, 16)); //read hexadecimal into long type
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