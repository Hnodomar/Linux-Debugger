#ifndef MINIDBG_BREAKPOINT_HPP
#define MINIDBG_BREAKPOINT_HPP

#include <cstdint>
#include <sys/ptrace.h>

namespace minidbg {
	class breakpoint {
	public:
		breakpoint() = default;
		breakpoint(pid_t pid, std::intptr_t addr)
			: m_pid{pid}, m_addr{addr}, m_enabled{false}, m_saved_data{}
		{}

		void enable() { //breakpoint member function to set breakpoint trap at desired address
			auto data = ptrace(PTRACE_PEEKDATA, m_pid, m_addr, nullptr); //PTRACE_PEEKDATA: ptrace request to read memory of traced process
			m_saved_data = static_cast<uint8_t>(data & 0xff); //save the bottom byte of original data at breakpt address
			uint64_t int3 = 0xcc; //trap: breakpoint instruction
			uint64_t data_with_int3 = ((data & ~0xff) | int3); //bottom byte send to 0xcc - breakpoint instruction
			ptrace(PTRACE_POKEDATA, m_pid, m_addr, data_with_int3); //PTRACE_POKEDATA: ptrace request to write to memory
			
			m_enabled = true;
		}	
		void disable() { //ptrace memory requests operate on whole words instead of bytes
			auto data = ptrace(PTRACE_PEEKDATA, m_pid, m_addr, nullptr); //so we need to read the word
			auto restored_data = ((data & ~0xff) | m_saved_data);		 //at the location and then
			ptrace(PTRACE_POKEDATA, m_pid, m_addr, restored_data);	     //overwrite the low byte with original data
			
			m_enabled = false;
		}

		auto is_enabled() const -> bool { return m_enabled; }
		auto get_address() const -> std::intptr_t { return m_addr; }

	private:
		pid_t m_pid;
		std::intptr_t m_addr;
		bool m_enabled;
		uint8_t m_saved_data; //data which used to be at the breakpoint address
	};
}

#endif