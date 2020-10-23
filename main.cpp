#include "linenoise.h"

#include <vector>
#include <iostream>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fstream>
#include <iomanip>
#include <stddef.h>


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


class debugger { //To interact with child process
    public:
        debugger (std::string prog_name, pid_t pid) //constructor to initialise m_prog_name & m_pid
            : m_prog_name{std::move(prog_name)}, m_pid{pid} {}
        
        void run();
    
	private:
		void continue_execution();
		void handle_command(const std::string&);
	
        std::string m_prog_name;
        pid_t m_pid;
};

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