#include "hw4.h"

int state = NONLOAD;
string file_path = "";
pid_t pid = 0;
char *code = NULL;
int code_size = 0;
vector<bp_t> bp_list;
elf_t elf;

void error(const char *func, int error_num)
{
    cout << "** FUNC [" << func << "] ERROR:" << strerror(error_num);
    exit(-1);
}
bool intext(const unsigned long addr)
{
    // cout << "elf.text_shdr.sh_addr:" << elf.text_shdr.sh_addr << endl;
    // cout << "elf.text_shdr.sh_addr + elf.text_shdr.sh_size:" << elf.text_shdr.sh_addr + elf.text_shdr.sh_size << endl;
    // cout << "addr:" << addr << endl;
    return (elf.text_shdr.sh_addr <= addr) && (addr < (elf.text_shdr.sh_addr + elf.text_shdr.sh_size));
}
void print8bytes(unsigned long code)
{
    for (int i = 0; i < 8; i++)
        cerr << hex << setw(2) << setfill('0') << (int)((unsigned char *)(&code))[i] << " ";
    cerr << setfill(' ');
}
void print8ascii(unsigned long code)
{
    for (int i = 0; i < 8; i++)
    {
        if (isprint((int)((char *)(&code))[i]))
            cerr << ((char *)(&code))[i];
        else
            cerr << ".";
    }
}
int getcode()
{
    ifstream f(file_path.c_str(), ios::in | ios::binary);
    f.seekg(0, f.end);
    int size = f.tellg();
    f.seekg(0, f.beg);
    code = (char *)malloc(sizeof(char) * size);
    f.read(code, size);
    f.close();
    return size;
}
void chkbp()
{
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) != 0)
        error("ptrace(PTRACE_GETREGS)", errno);

    for (int i = 0; i < (int)bp_list.size(); i++)
    {
        if (bp_list[i].addr > regs.rip)
            bp(bp_list[i].addr);
    }
}
void chkstat()
{
    int status;
    if (waitpid(pid, &status, 0) < 0)
        error("waitpid", errno);
    if (WIFEXITED(status))
    {
        if (WIFSIGNALED(status))
            cout << "** child process " << pid << " terminiated by signal (code " << WTERMSIG(status) << ")" << endl;
        else
            cout << "** child process " << pid << " terminiated normally (code " << status << ")" << endl;
        pid = 0;
        state = LOADED;
    }
    if (WIFSTOPPED(status))
    {
        if (WSTOPSIG(status) == SIGTRAP)
        {
            struct user_regs_struct regs;
            if (ptrace(PTRACE_GETREGS, pid, 0, &regs) != 0)
                error("ptrace(PTRACE_GETREGS)", errno);
            for (int i = 0; i < (int)bp_list.size(); i++)
            {
                if (bp_list[i].addr == regs.rip - 1)
                {
                    cout << "** breakpoint @ ";
                    disasm(bp_list[i].addr, 1);
                    if (ptrace(PTRACE_POKETEXT, pid, bp_list[i].addr, bp_list[i].orig_code) != 0)
                        error("ptrace(PTRACE_POKETEXT)", errno);
                    regs.rip--;
                    if (ptrace(PTRACE_SETREGS, pid, 0, &regs) != 0)
                        error("ptrace(PTRACE_SETREGS)", errno);
                }
                else if (bp_list[i].addr == regs.rip)
                {
                    cout << "** breakpoint @ ";
                    disasm(bp_list[i].addr, 1);
                    if (ptrace(PTRACE_POKETEXT, pid, bp_list[i].addr, bp_list[i].orig_code) != 0)
                        error("ptrace(PTRACE_POKETEXT)", errno);
                    regs.rip--;
                    // if (ptrace(PTRACE_SETREGS, pid, 0, &regs) != 0)
                    //     error("ptrace(PTRACE_SETREGS)", errno);
                }
            }
        }
        else
        {
            cout << "** child process " << pid << " terminiated by signal (code" << WSTOPSIG(status) << ")" << endl;
        }
    }
}
void quit()
{
    if (elf.str_tab != NULL)
    {
        free(elf.str_tab);
    }
    if (pid)
    {
        kill(pid, SIGTERM);
        pid = 0;
    }
    if (code != NULL)
    {
        free(code);
        code = NULL;
    }
    exit(0);
}
void help()
{
    cerr << "- break {instruction-address}: add a break point\n";
    cerr << "- cont: continue execution\n";
    cerr << "- delete {break-point-id}: remove a break point\n";
    cerr << "- disasm addr: disassemble instructions in a file or a memory region\n";
    cerr << "- dump addr [length]: dump memory content\n";
    cerr << "- exit: terminate the debugger\n";
    cerr << "- get reg: get a single value from a register\n";
    cerr << "- getregs: show registers\n";
    cerr << "- help: show this message\n";
    cerr << "- list: list break points\n";
    cerr << "- load {path/to/a/program}: load a program\n";
    cerr << "- run: run the program\n";
    cerr << "- vmmap: show memory layout\n";
    cerr << "- set reg val: get a single value to a register\n";
    cerr << "- si: step into instruction\n";
    cerr << "- start: start the program and stop at the first instruction\n";
}
void del(int id)
{
    if (state != RUNNING)
    {
        cout << "**   The state should be RUNNING!\n";
        return;
    }
    for (int i = 0; i < (int)bp_list.size(); i++)
    {
        if (bp_list[i].id == id)
        {
            cout << "** breakpoint " << id << " deleted.\n";
            // disasm(bp_list[id].addr, 1);
            if (ptrace(PTRACE_POKETEXT, pid, bp_list[id].addr, bp_list[id].orig_code) != 0)
                error("ptrace(PTRACE_POKETEXT)", errno);
            bp_list.erase(bp_list.begin() + id);
            return;
        }
    }
    cout << "**  bp id is not found!\n";
}
void get(string reg)
{
    if (state != RUNNING)
    {
        cout << "** The state should be RUNNING!\n";
        return;
    }
    unsigned long long val;
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) != 0)
        error("ptrace(PTRACE_GETREGS)", errno);
    if (reg == "rax")
        val = regs.rax;
    else if (reg == "rbx")
        val = regs.rbx;
    else if (reg == "rcx")
        val = regs.rcx;
    else if (reg == "rdx")
        val = regs.rdx;
    else if (reg == "r8")
        val = regs.r8;
    else if (reg == "r9")
        val = regs.r9;
    else if (reg == "r10")
        val = regs.r10;
    else if (reg == "r11")
        val = regs.r11;
    else if (reg == "r12")
        val = regs.r12;
    else if (reg == "r13")
        val = regs.r13;
    else if (reg == "r14")
        val = regs.r14;
    else if (reg == "r15")
        val = regs.r15;
    else if (reg == "rdi")
        val = regs.rdi;
    else if (reg == "rsi")
        val = regs.rsi;
    else if (reg == "rbp")
        val = regs.rbp;
    else if (reg == "rsp")
        val = regs.rsp;
    else if (reg == "rip")
        val = regs.rip;
    else if (reg == "flags")
        val = regs.eflags;
    else
    {
        cout << "** [reg] is not found!\n";
        return;
    }
    cerr << reg << " = " << dec << val << " (0x" << hex << val << ")\n";
}
void set(string reg, unsigned long long val)
{
    if (state != RUNNING)
    {
        cout << "** The state should be RUNNING!\n";
        return;
    }

    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) != 0)
        error("ptrace(PTRACE_GETREGS)", errno);
    if (reg == "rax")
        regs.rax = val;
    else if (reg == "rbx")
        regs.rbx = val;
    else if (reg == "rcx")
        regs.rcx = val;
    else if (reg == "rdx")
        regs.rdx = val;
    else if (reg == "r8")
        regs.r8 = val;
    else if (reg == "r9")
        regs.r9 = val;
    else if (reg == "r10")
        regs.r10 = val;
    else if (reg == "r11")
        regs.r11 = val;
    else if (reg == "r12")
        regs.r12 = val;
    else if (reg == "r13")
        regs.r13 = val;
    else if (reg == "r14")
        regs.r14 = val;
    else if (reg == "r15")
        regs.r15 = val;
    else if (reg == "rdi")
        regs.rdi = val;
    else if (reg == "rsi")
        regs.rsi = val;
    else if (reg == "rbp")
        regs.rbp = val;
    else if (reg == "rsp")
        regs.rsp = val;
    else if (reg == "rip")
        regs.rip = val;
    else if (reg == "flags")
        regs.eflags = val;
    else
        cout << "** [reg] is not found!\n";

    if (ptrace(PTRACE_SETREGS, pid, 0, &regs) != 0)
        error("ptrace(PTRACE_SETREGS)", errno);
}
void getregs()
{
    if (state != RUNNING)
    {
        cout << "** The state should be RUNNING!\n";
        return;
    }
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) != 0)
        error("ptrace(PTRACE_GETREGS)", errno);
    cerr << hex
         << left << setw(7) << "RAX: " << left << setw(10) << regs.rax << "\t"
         << left << setw(7) << "RBX: " << left << setw(10) << regs.rbx << "\t"
         << left << setw(7) << "RCX: " << left << setw(10) << regs.rcx << "\t"
         << left << setw(7) << "RDX: " << left << setw(10) << regs.rdx << "\n"
         << left << setw(7) << "R8: " << left << setw(10) << regs.r8 << "\t"
         << left << setw(7) << "R9: " << left << setw(10) << regs.r9 << "\t"
         << left << setw(7) << "R10: " << left << setw(10) << regs.r10 << "\t"
         << left << setw(7) << "R11: " << left << setw(10) << regs.r11 << "\n"
         << left << setw(7) << "R12: " << left << setw(10) << regs.r12 << "\t"
         << left << setw(7) << "R13: " << left << setw(10) << regs.r13 << "\t"
         << left << setw(7) << "R14: " << left << setw(10) << regs.r14 << "\t"
         << left << setw(7) << "R15: " << left << setw(10) << regs.r15 << "\n"
         << left << setw(7) << "RDI: " << left << setw(10) << regs.rdi << "\t"
         << left << setw(7) << "RSI: " << left << setw(10) << regs.rsi << "\t"
         << left << setw(7) << "RBP: " << left << setw(10) << regs.rbp << "\t"
         << left << setw(7) << "RSP: " << left << setw(10) << regs.rsp << "\n"
         << left << setw(7) << "RIP: " << left << setw(10) << regs.rip << "\t"
         << left << setw(7) << "FLAGS: " << left << setw(16) << setfill('0') << right << regs.eflags << "\n";
    cerr << setfill(' ');
}
void si()
{
    if (state != RUNNING)
    {
        cout << "** The state should be RUNNING!\n";
        return;
    }
    chkbp();
    if (ptrace(PTRACE_SINGLESTEP, pid, 0, 0) < 0)
        error("ptrace(PTRACE_SINGLESTEP)", errno);
    chkstat();
}
void list()
{
    for (int i = 0; i < (int)bp_list.size(); i++)
        cerr << "\t" << bp_list[i].id << ":\t" << hex << bp_list[i].addr << endl;
}
void bp(unsigned long bp_addr)
{
    if (state != RUNNING)
    {
        cout << "** The state should be RUNNING!\n";
        return;
    }
    if (!bp_addr)
    {
        cout << "** No addr is given!\n";
        return;
    }

    unsigned long code = ptrace(PTRACE_PEEKTEXT, pid, bp_addr, 0);

    if ((code & 0xff) == 0xcc) // already set bp
        return;
    if (ptrace(PTRACE_POKETEXT, pid, bp_addr, (code & 0xffffffffffffff00) | 0xcc) != 0)
        error("ptrace(POKETEXT)", errno);

    for (int i = 0; i < (int)bp_list.size(); i++)
    {
        if (bp_list[i].addr == bp_addr) // already add into bp list
            return;
    }

    bp_t b;
    b.id = bp_list.size();
    b.addr = bp_addr;
    b.orig_code = code;
    bp_list.push_back(b);
    // cout << "**   set bp @ ";
    // disasm(bp_addr, 1);
}
void vmmap()
{
    if (state != RUNNING)
    {
        cout << "** State should be RUNNING!" << endl;
        return;
    }

    string dir = "/proc/" + to_string(pid) + "/maps";
    char *line, *token;
    size_t len;
    FILE *fp;
    if ((fp = fopen(dir.c_str(), "r")) == NULL)
        error("fopen", errno);
    while (getline(&line, &len, fp) != EOF)
    {
        /*  line sample: 00600000-00601000 rw-p 00000000 08:02 2622929   /home/johnny/code/unix_prog/hw4/sample/hello64  */
        if ((token = strtok(line, "-")) != NULL) // 00600000 address
            cerr << setw(16) << setfill('0') << right << string(token) << "-";
        if ((token = strtok(NULL, " ")) != NULL) // 00601000 address
            cerr << setw(16) << setfill('0') << right << string(token) << " ";
        if ((token = strtok(NULL, " p")) != NULL) // rw-p     perms
            cerr << setfill(' ') << string(token) << " ";
        token = strtok(NULL, " ");               // 00000000 offset
        token = strtok(NULL, " ");               // 08:02    dev
        if ((token = strtok(NULL, " ")) != NULL) // 2622929  inode
            cerr << setw(9) << left << string(token);
        if ((token = strtok(NULL, " ")) != NULL) // /home/johnny/code/unix_prog/hw4/sample/hello64    pathname
            cerr << string(token);
    }
}
void dump(unsigned long dump_addr)
{
    if (state != RUNNING)
    {
        cout << "** State should be RUNNING!" << endl;
        return;
    }
    if (!dump_addr)
    {
        cout << "** no addr is given.\n";
        return;
    }
    if (!intext(dump_addr))
    {
        cout << "** the address is out of the range of the text segment\n";
        return;
    }

    unsigned long code1, code2;
    for (int i = 0; i < DUMP_MAX; i++, dump_addr += 16)
    {
        code1 = ptrace(PTRACE_PEEKTEXT, pid, dump_addr, 0);
        code2 = ptrace(PTRACE_PEEKTEXT, pid, dump_addr + 8, 0);
        cerr << hex << setw(12) << setfill(' ') << right << dump_addr << ": ";
        print8bytes(code1);
        print8bytes(code2);
        cerr << "|";
        print8ascii(code1);
        print8ascii(code2);
        cerr << "|\n";
    }
}
void disasm(unsigned long dis_addr, int size)
{
    if (state != RUNNING)
    {
        cout << "** State should be RUNNING!\n"
             << endl;
        return;
    }
    if (!dis_addr)
    {
        cout << "** No addr is given.\n";
        return;
    }
    if (!intext(dis_addr))
    {
        cout << "** the address is out of the range of the text segment\n";
        return;
    }

    if (code == NULL)
        code_size = getcode();
    long long offset = elf.text_shdr.sh_offset + (dis_addr - elf.text_shdr.sh_addr);
    char *cur_code = code + offset;

    csh handle;
    cs_insn *insn;
    size_t count;
    uint64_t cur_addr = (uint64_t)dis_addr;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
        error("cs_open", errno);
    if ((count = cs_disasm(handle, (uint8_t *)cur_code, (size_t)code_size, cur_addr, (size_t)size, &insn)) > 0)
    {
        for (int i = 0; i < (int)count; i++)
        {
            unsigned char bytes[16];
            char bits[128] = "";
            memcpy(bytes, insn[i].bytes, insn[i].size);
            for (int j = 0; j < insn[i].size; j++) // bytes to bits
                snprintf(&bits[j * 3], 4, "%2.2x ", bytes[j]);

            if (intext(insn[i].address))
                cerr << hex << right << setw(12) << insn[i].address << ":  "
                     << left << setw(32) << bits
                     << left << setw(7) << insn[i].mnemonic
                     << left << setw(7) << insn[i].op_str << endl;
            else
            {
                cerr << "** the address is out of the range of the text segment\n";
                break;
            }
        }
        cs_free(insn, count);
    }
    else
        cout << "**   Can not disassemble code!\n";
    cs_close(&handle);
}
void cont()
{
    if (state != RUNNING)
    {
        cout << "**    The state is not RUNNING!\n";
        return;
    }
    chkbp();
    if (ptrace(PTRACE_CONT, pid, 0, 0) < 0)
        error("ptrace(PTRACE_CONT)", errno);
    chkstat();
}
void run()
{
    if (state == RUNNING)
    {
        cont();
    }
    else if (state == LOADED)
    {
        start();
        cont();
    }
    else
    {
        cout << "**   The state should be RUNNING or LOADED!\n";
    }
}
void start()
{
    if (state != LOADED)
    {
        cout << "** The state is not LOADED!\n";
        return;
    }
    if (pid)
    {
        cout << "** program " << file_path << " is already running\n";
        return;
    }
    if ((pid = fork()) < 0)
        error("fork", errno);
    else if (pid == 0)
    {
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0)
            error("ptrace(PTRACE_TRACEME)", errno);
        char **arg = {NULL};
        if (execvp(file_path.c_str(), arg) < 0)
            error("execvp", errno);
    }
    else
    {
        int status;
        if (waitpid(pid, &status, 0) < 0)
            error("waitpid", errno);
        if (ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_EXITKILL) < 0)
            error("ptrace(PTRACE_SETOPTIONS)", errno);
        cout << "** pid " << dec << pid << endl;
        state = RUNNING;
    }
}
void load(string file_path)
{
    if (state == LOADED)
    {
        cout << "**   The state is already LOADED!\n";
        return;
    }
    FILE *fp;
    elf.str_tab = NULL;
    int str_shdr_offset;
    if ((fp = fopen(file_path.c_str(), "rb")) == NULL)
        error("fopen", errno);
    elf.fp = fp;
    fread(&(elf.ehdr), 1, sizeof(Elf64_Ehdr), elf.fp);
    if (elf.ehdr.e_ident[EI_MAG0] == 0x7f &&
        elf.ehdr.e_ident[EI_MAG1] == 'E' &&
        elf.ehdr.e_ident[EI_MAG2] == 'L' &&
        elf.ehdr.e_ident[EI_MAG3] == 'F')
    {

        if (elf.ehdr.e_ident[EI_CLASS] == ELFCLASS64)
        {
            /*  Find String Section Header  */
            /*  section header table's file offset + section header table index of the string table * section header size   */
            str_shdr_offset = elf.ehdr.e_shoff + (elf.ehdr.e_shstrndx) * sizeof(Elf64_Shdr);
            fseek(elf.fp, str_shdr_offset, SEEK_SET);
            fread(&(elf.str_shdr), 1, sizeof(Elf64_Shdr), elf.fp);
            elf.str_tab = (char *)malloc(sizeof(char) * elf.str_shdr.sh_size);
            fseek(elf.fp, elf.str_shdr.sh_offset, SEEK_SET);
            fread(elf.str_tab, elf.str_shdr.sh_size, sizeof(char), elf.fp);
            // cout<<"**   String Seciotn Header.offset: 0x"<<hex<<elf.str_shdr.sh_offset<<endl;
            // cout<<"**   String Seciotn Header.size: 0x"<<hex<<elf.str_shdr.sh_size<<endl;

            /*  Find Text Section Header    */
            Elf64_Shdr tmp_shdr;
            fseek(elf.fp, elf.ehdr.e_shoff, SEEK_SET);
            for (int i = 0; i < elf.ehdr.e_shnum; i++)
            {
                fread(&(tmp_shdr), 1, sizeof(Elf64_Shdr), elf.fp);
                if (strcmp((elf.str_tab + tmp_shdr.sh_name), ".text") == 0)
                {
                    elf.text_shdr = tmp_shdr;
                    // cout<<"**   .text INFO"<<endl;
                    // cout<<"**   addr:   0x"<<hex<<elf.text_shdr.sh_addr<<endl;
                    // cout<<"**   offset: 0x"<<hex<<elf.text_shdr.sh_offset<<endl;
                    // cout<<"**   size:   0x"<<hex<<elf.text_shdr.sh_size<<endl;
                    break;
                }
            }
        }
        else
        {
            cout << "**   Not 64-bits program!\n";
            return;
        }
    }
    else
    {
        cout << "**   Not ELF file!\n";
        return;
    }
    cout << "** program '" << file_path << "' loaded. entry point 0x" << hex << elf.ehdr.e_entry << "\n";
    state = LOADED;
}
void split(const string cmd_line, vector<string> &cmd_table)
{
    cmd_table.clear();
    istringstream ss(cmd_line);
    string temp;
    while (ss >> temp)
        cmd_table.push_back(temp);
}
int main(const int argc, const char *argv[])
{
    string cmd_line, cmd, arg1, arg2, fix_out = "sdb> ";
    vector<string> cmd_table;
    ifstream f;

    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "-s") == 0)
        { //[-s script]
            string script_path = argv[++i];
            f.open("./" + script_path, ifstream::in);
        }
        else
        { //[program]
            file_path = argv[i];
            load(file_path);
        }
    }

    while (1)
    {
        if (f.is_open())
        {
            if (!getline(f, cmd_line))
                quit();
        }
        else
        {
            cout << fix_out;
            getline(cin, cmd_line);
        }
        split(cmd_line, cmd_table);
        cmd = "";
        arg1 = "";
        arg2 = "";
        if (cmd_table.size() >= 1)
            cmd = cmd_table[0];
        if (cmd_table.size() >= 2)
            arg1 = cmd_table[1];
        if (cmd_table.size() >= 3)
            arg2 = cmd_table[2];

        if (cmd == "break" || cmd == "b")
        {
            bp(strtoul(arg1.c_str(), NULL, 16));
        }
        else if (cmd == "cont" || cmd == "c")
        {
            cont();
        }
        else if (cmd == "delete")
        {
            if (!arg1.size())
            {
                cout << "**   No bp id is given!\n";
                continue;
            }
            del(atoi(arg1.c_str()));
        }
        else if (cmd == "disasm" || cmd == "d")
        {
            disasm(strtoul(arg1.c_str(), NULL, 16), DISASM_MAX);
        }
        else if (cmd == "dump" || cmd == "x")
        {
            dump(strtoul(arg1.c_str(), NULL, 16));
        }
        else if (cmd == "exit" || cmd == "q")
        {
            quit();
        }
        else if (cmd == "get" || cmd == "g")
        {
            get(arg1);
        }
        else if (cmd == "getregs")
        {
            getregs();
        }
        else if (cmd == "help" || cmd == "h")
        {
            help();
        }
        else if (cmd == "list" || cmd == "l")
        {
            list();
        }
        else if (cmd == "load")
        {
            file_path = arg1;
            load(file_path);
        }
        else if (cmd == "run" || cmd == "r")
        {
            run();
        }
        else if (cmd == "vmmap" || cmd == "m")
        {
            vmmap();
        }
        else if (cmd == "set" || cmd == "s")
        {
            set(arg1, strtoull(arg2.c_str(), NULL, 16));
        }
        else if (cmd == "si")
        {
            si();
        }
        else if (cmd == "start")
        {
            start();
        }
        else
        {
            cerr << "**   Non Defined Command!\n";
            continue;
        }
    }
    return 0;
}