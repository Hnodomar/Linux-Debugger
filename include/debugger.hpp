#ifndef MINIDBG_DEBUGGER_HPP
#define MINIDBG_DEBUGGER_HPP

#include <utility>
#include <string>
#include <linux/types.h>
#include <unordered_map>

#include "breakpoint.hpp"
#include "dwarf/dwarf++.hh"
#include "elf/elf++.hh"

namespace minidbg {
	class debugger { //To interact with child process
		public:
			debugger (std::string prog_name, pid_t pid) //constructor to initialise m_prog_name & m_pid
				: m_prog_name{std::move(prog_name)}, m_pid{pid} 
			{
				//open instead of fstream since elf loader needs UNIX file descriptor to pass to mmap
				//so that it can just map the file into memory rather than reading it a bit at a time

			}
        
			void run();
			void set_breakpoint_at_address(std::intptr_t addr);
			void dump_registers();
			std::intptr_t offset_address(std::string& addr);
			
			
		private:
			void handle_command(const std::string& line);
			void continue_execution();
			auto get_pc() -> uint64_t;
			void set_pc(uint64_t pc);
			void step_over_breakpoint();
			void wait_for_signal();
			
			auto read_memory(uint64_t address) -> uint64_t;
			void write_memory(uint64_t adress, uint64_t value);
			
			std::unordered_map<std::intptr_t,breakpoint> m_breakpoints;
			std::string m_prog_name;
			pid_t m_pid;
	};
}

#endif
