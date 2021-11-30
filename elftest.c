#include "stdio.h"
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <elf.h>

unsigned char stub_code[] =	
							"\x83\xec\x0c"			// sub	$0xc, %esp
							"\x68\x68\x17\x0\x0"	// push $0xFB0 	在echo中，字符串将被保存在0xFB0处
							"\xe8\x41\x0\x0\x0"	// call printf
							"\x83\xc4\x10"			// add	$0x10, %esp
//							"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"  // nop 填充，使得代码正好长0x10
							; 

#define RELJMP 	11

int main(int argc, char* argv[]) 
{
	int fd, i;

	unsigned char* base;
	unsigned int size, * off, offs;
	unsigned long stub, orig;
	unsigned long clen = sizeof(stub_code) - 1;	// 除去最后一个'\0'
	Elf32_Ehdr* ehdr;
	Elf32_Phdr* phdrs;
	Elf32_Shdr* shdrs;

	// 这是一个e9 jmp rel32指令
	stub_code[RELJMP] = 0xe9;
	off = (unsigned int*) &stub_code[RELJMP + 1];

	// __asm__ __volatile__("xchg %bx, %bx");
	fd = open(argv[1], O_RDWR);
	// __asm__ __volatile__("xchg %bx, %bx");
	size = lseek(fd, 0, SEEK_END);
	// __asm__ __volatile__("xchg %bx, %bx");
	// base = fd;
	base = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);

	// __asm__ __volatile__("xchg %bx, %bx");
	ehdr = (Elf32_Ehdr*) base;
	phdrs = (Elf32_Phdr*) &base[ehdr->e_phoff];
	shdrs = (Elf32_Shdr*) &base[ehdr->e_shoff];
	orig = ehdr->e_entry;

	// 此处开始修改程序入口, 假设shellcode长0x20,则应放在0x1000 - 0x20 - 0x1处
	stub = 0xFF0;
	// __asm__ __volatile__("xchg %bx, %bx");
	ehdr->e_entry = (Elf32_Addr)stub;				// 令程序段入口为elf头的填充区地址
	// 修改phdr的offset为0xFF0, 最后bochs将根据这个offset加载文件代码
	phdrs->p_offset = (Elf32_Off)stub;

	// 此处开始填充代码
	// __asm__ __volatile__("xchg %bx, %bx");
	memcpy(base + 0xFF0, stub_code, 11);
	memcpy(base + 0xFF0 + 0xb, "\x00", 1);
	memcpy(base + 0xFF0 + 0xb + 0x1, stub_code + 12, 4);
	
	// 此处开始修改程序头的文件大小
	phdrs[0].p_filesz += clen;
	phdrs[0].p_memsz += clen;


	munmap(base, size);
}
