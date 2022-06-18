#include <stdio.h>
#include <string.h>
#include <iostream>
#include <sstream>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <iomanip>
#include <fstream>
#include <capstone/capstone.h>
#include <vector>
#include <elf.h>

using namespace std;

/*  State Type  */
#define NONLOAD 0
#define LOADED 1
#define RUNNING 2

#define DISASM_MAX 10
#define DUMP_MAX 5 // 8 bytes x 2 for one time.

typedef struct elf_s
{
    FILE *fp;

    Elf64_Ehdr ehdr;      //  ELF header
    Elf64_Shdr str_shdr;  //  string section header
    char *str_tab;        //  string tables
    Elf64_Shdr text_shdr; //  text section header
} elf_t;
typedef struct bp_s
{
    int id;
    unsigned long addr;
    unsigned long orig_code;
} bp_t;

void cont();
void run();
void start();
void load(string);
void disasm(unsigned long, int);
void bp(unsigned long);
void list();
void si();
void getregs();
void set(string, unsigned long long);
void get(string);
void del(int);
void help();
void quit();
void dump(unsigned long);
void vmmap();

void print8bytes(unsigned long);
int getcode();
void chkstat();
void chkbp();
void split(const string, vector<string> &);
void error(const char *, int);