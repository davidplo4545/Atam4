#include <stdio.h>
#include "elf64.h"
#include <string.h>
#include <sys/types.h> // TODO: check if allowed
#include <unistd.h> // TODO: check if allowed
#include <sys/ptrace.h> // TODO: check if allowed
#include <stdlib.h> // TODO: check if allowed
#include <sys/wait.h> // TODO: check if allowed
#include <sys/user.h> // TODO: check if allowed
#define	ET_NONE	0	//No file type
#define	ET_REL	1	//Relocatable file
#define	ET_EXEC	2	//Executable file
#define	ET_DYN	3	//Shared object file
#define	ET_CORE	4	//Core file


/* symbol_name		- The symbol (maybe function) we need to search for.
 * exe_file_name	- The file where we search the symbol in.
 * error_val		- If  1: A global symbol was found, and defined in the given executable.
 * 			- If -1: Symbol not found.
 *			- If -2: Only a local symbol was found.
 * 			- If -3: File is not an executable.
 * 			- If -4: The symbol was found, it is global, but it is not defined in the executable.
 * return value		- The address which the symbol_name will be loaded to, if the symbol was found and is global.
 */


Elf64_Off getStringHeaderSectionOffset(FILE* fptr, Elf64_Ehdr elfHeader)
{
    Elf64_Shdr headerStringsSectionTable;
    fseek(fptr, elfHeader.e_shoff + elfHeader.e_shentsize * elfHeader.e_shstrndx, SEEK_SET);
    fread(&headerStringsSectionTable, sizeof(headerStringsSectionTable), 1, fptr);
    return headerStringsSectionTable.sh_offset;
}



Elf64_Shdr findSectionOffset(FILE *fptr, Elf64_Ehdr elfHeader, char* sectionName)
{
    Elf64_Off sectionHeadersOffset = elfHeader.e_shoff;
    Elf64_Word sectionHeadersNum = elfHeader.e_shnum;
    Elf64_Half headerSectionSize = elfHeader.e_shentsize;

    Elf64_Off sectionStringTableOff = getStringHeaderSectionOffset(fptr, elfHeader);
    char currName[1024];
    for(int i=0;i<sectionHeadersNum;i++)
    {
        Elf64_Shdr sectionHeader;
        fseek(fptr, sectionHeadersOffset + (i * headerSectionSize), SEEK_SET);
        fread(&sectionHeader, headerSectionSize,1, fptr);
        Elf64_Word headerNameIndex = sectionHeader.sh_name;
        // check if correct string table
        fseek(fptr, sectionStringTableOff + headerNameIndex, SEEK_SET);
        fread(currName, 1, sizeof(currName), fptr);
        if(strcmp(currName, sectionName) == 0)
        {
            return sectionHeader;
        }
    }
}

void getFinalResult(Elf64_Sym entry, Elf64_Ehdr elfHeader, int *error_val, int found)
{
    if(elfHeader.e_type != 2)
    {
        *error_val = -3;
        return;
    }
    if(found == 0)
    {
        *error_val = -1;
        return;
    }
    // this is an executable
    int bind = ELF64_ST_BIND(entry.st_info); // (GLOBAL OR WHAT NOT)
    if(bind == 1) // this is global
    {
        if(entry.st_shndx != 0) // = not Shared Object
            *error_val = 1;
        else
            *error_val = -4; // shared object TODO: Find dynamic address
    }
    else
        *error_val = -2;
}
unsigned long find_symbol_dynamic(char* symbol_name, char* exe_file_name, int* error_val) {
    FILE* fptr;
    fptr = fopen(exe_file_name, "r");
    Elf64_Ehdr elfHeader;

    fread(&elfHeader, sizeof(char), sizeof(elfHeader), fptr);

    Elf64_Off sectionHeaderOffset = elfHeader.e_shoff;
    Elf64_Half sectionHeadersNum = elfHeader.e_shnum;
    Elf64_Off stringTableOffset = findSectionOffset(fptr, elfHeader, ".dynstr").sh_offset;

    Elf64_Off dynTabOffset;
    Elf64_Sym currEntry;
    Elf64_Sym reqEntry;
    int found = 0;
    for(int i=0;i<sectionHeadersNum;i++)
    {
        Elf64_Shdr sectionHeader;
        fseek(fptr, sectionHeaderOffset+ (i*elfHeader.e_shentsize), SEEK_SET);
        fread(&sectionHeader, elfHeader.e_shentsize,1, fptr);
        if(sectionHeader.sh_type == 11)
        {
            // this is the section of the dynamic table (meant for Dolev)
            dynTabOffset = sectionHeader.sh_offset;

            Elf64_Xword entrySize = sectionHeader.sh_entsize;

            int numOfEntries = sectionHeader.sh_size / entrySize;
            // check all the symbols to find the one with the correct name
            for(unsigned long j=0;j<numOfEntries;j++)
            {
                fseek(fptr, dynTabOffset + entrySize * j, SEEK_SET);
                fread(&currEntry, entrySize,1,fptr);
                char symbolName[512];
                fseek(fptr, stringTableOffset + currEntry.st_name, SEEK_SET);
                fread(symbolName, 1, sizeof(symbolName), fptr);
                if(strcmp(symbolName, symbol_name) == 0)
                {
                    fclose(fptr);
                    return j;
                }
            }
        }
    }
    fclose(fptr);

}

Elf64_Addr find_relocation_address(unsigned long index, char* exe_file_name)
{
    FILE* fptr;
    fptr = fopen(exe_file_name, "r");

    Elf64_Ehdr elfHeader;
    fread(&elfHeader, sizeof(char), sizeof(elfHeader), fptr);

    Elf64_Shdr relocationHeader = findSectionOffset(fptr, elfHeader, ".rela.plt");

    int numOfEntries = relocationHeader.sh_size / relocationHeader.sh_entsize;

    Elf64_Off relocationTableOffset = relocationHeader.sh_offset;
    Elf64_Rela currEntry;
    // check all the symbols to find the one with the correct name
    for(int j=0;j<numOfEntries;j++)
    {
        fseek(fptr, relocationTableOffset + sizeof(currEntry) * j, SEEK_SET);
        fread(&currEntry, sizeof(currEntry),1,fptr);

        if(ELF64_R_SYM(currEntry.r_info) == index)
        {
            fclose(fptr);
            return currEntry.r_offset; // returns the address of the function in the got
        }

    }
    fclose(fptr);
    return -1;
}
unsigned long find_symbol_static(char* symbol_name, char* exe_file_name, int* error_val) {
    FILE* fptr;
    fptr = fopen(exe_file_name, "r");
    Elf64_Ehdr elfHeader;

    fread(&elfHeader, sizeof(char), sizeof(elfHeader), fptr);

    Elf64_Off sectionHeaderOffset = elfHeader.e_shoff;
    Elf64_Half sectionHeadersNum = elfHeader.e_shnum;
    Elf64_Off stringTableOffset = findSectionOffset(fptr, elfHeader, ".strtab").sh_offset;

    Elf64_Off symTabOffset;
    Elf64_Sym currEntry;
    Elf64_Sym reqEntry;
    int found = 0;
    for(int i=0;i<sectionHeadersNum;i++)
    {
        Elf64_Shdr sectionHeader;
        fseek(fptr, sectionHeaderOffset+ (i*elfHeader.e_shentsize), SEEK_SET);
        fread(&sectionHeader, elfHeader.e_shentsize,1, fptr);
        if(sectionHeader.sh_type == 2)
        {
            // this is the section of the symbol table (meant for Dolev)
            symTabOffset = sectionHeader.sh_offset;

            Elf64_Xword entrySize = sectionHeader.sh_entsize;

            int numOfEntries = sectionHeader.sh_size / entrySize;
            // check all the symbols to find the one with the correct name
            for(int j=0;j<numOfEntries;j++)
            {
                fseek(fptr, symTabOffset + entrySize * j, SEEK_SET);
                fread(&currEntry, entrySize,1,fptr);
                char symbolName[256];
                fseek(fptr, stringTableOffset + currEntry.st_name, SEEK_SET);
                fread(symbolName, 1, sizeof(symbolName), fptr);
                if(strcmp(symbolName, symbol_name) == 0)
                {
                    // if its global or not found yet than save it
                    if(ELF64_ST_BIND(currEntry.st_info) == 1 || found == 0)
                    {
                        reqEntry = currEntry;
                        found = 1;
                    }
                }
            }
        }
    }

    if(found == 0)
    {
        // couldn't find the symbol
        getFinalResult(reqEntry, elfHeader, error_val, found);
        fclose(fptr);
        return 0;
    }
    else
    {
        getFinalResult(reqEntry, elfHeader, error_val, found);
        if(*error_val < 0)
            return 0;
        fclose(fptr);
        return reqEntry.st_value;
    }
}

pid_t run_target(const char* program, char* const args[])
{
    pid_t pid;
    pid = fork();
    if(pid > 0)
    {
        return pid;
    }
    else if(pid == 0)
    {
        ptrace(PTRACE_TRACEME,0,NULL,NULL);
        execv(program,args);
    }
}


unsigned long setBreakpoint(unsigned long addr, pid_t child_pid)
{
    long data = ptrace(PTRACE_PEEKTEXT, child_pid, (void*) addr, NULL);
    unsigned long data_trap = (data & 0xFFFFFFFFFFFFFF00) | 0xCC;
    ptrace(PTRACE_POKETEXT, child_pid, (void*)addr, (void*)data_trap);
    return data;

}
void run_counter_debugger(pid_t child_pid, unsigned long addr)
{
    int wait_status;
    int call_counter = 0; //count the number of the function has been called
    int open_counter = 0;
    unsigned long retAddress;
    unsigned long old_ret_data;
    struct user_regs_struct regs;

    while(1){ //while the function has been called TODO: handle WIFEXITED
        wait(&wait_status);
        unsigned long old_data = setBreakpoint(addr, child_pid); // set function entry breakpoint

        ptrace(PTRACE_CONT, child_pid, NULL, NULL);

        wait(&wait_status); // waiting for breakpoint

        ptrace(PTRACE_GETREGS,child_pid, 0, &regs);
        retAddress = regs.rsp;
        unsigned long firstParam = regs.rdi;

        regs.rip -=1;
        if(open_counter == 0)
        {
            call_counter++;
            old_ret_data = setBreakpoint(retAddress,child_pid);
            printf("PRF:: run #%d first parameter is %ld\n", call_counter, firstParam);
        }
        open_counter++;

        ptrace(PTRACE_POKETEXT, child_pid, (void*)addr, (void*)old_data);
        ptrace(PTRACE_SETREGS,child_pid, 0, &regs);

        // single step
        ptrace(PTRACE_SINGLESTEP, child_pid, NULL, NULL);
        ptrace(PTRACE_CONT, child_pid, NULL, NULL);

        // TODO: stop on return
        open_counter--;

    }
}


int main(int argc, char *const argv[]) {
    int err = 0;
    unsigned long addr = find_symbol_static(argv[1], argv[2], &err);

    if (err == -3)
    {
        printf("PRF:: %s not an executable!\n", argv[2]);
        return 0;
    }
    else if (err == -1)
    {
        printf("PRF:: %s not found! :(\n", argv[1]);
        return 0;
    }
    else if (err == -2)
    {
        printf("PRF:: %s is not a global symbol!\n", argv[1]);
        return 0;
    }
    else if(err == -4)
    {
        unsigned long index = find_symbol_dynamic(argv[1], argv[2], &err);
        addr = find_relocation_address(index, argv[2]);
    }

    char* const* tempArgs = argv+1;

    if (addr > 0) // TODO: check
        printf("%s will be loaded to 0x%lx\n", argv[1], addr);

    // TODO:Debugger
//    pid_t child_pid;
//    child_pid = run_target(argv[2],tempArgs);
//    run_counter_debugger(child_pid, addr);

    return 0;
}
