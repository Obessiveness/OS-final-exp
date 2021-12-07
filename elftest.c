#include "stdio.h"
#include "string.h"
// #include <fcntl.h>
// #include <string.h>
// #include <sys/mman.h>
#include <elf.h>
#define MAX 0x2000
unsigned char stub_code[] = 	
							"\x83\xec\x0c"			// sub	$0xc, %esp
							"\x68\x80\x17\x0\x0"	// push $0xFB0 	在echo中，字符串将被保存在0xFB0处
							"\xe8\x49\x0\x0\x0"	// call printf
							"\x83\xc4\x10"			// add	$0x10, %esp
							"\xe8\x33\x0\x0\x0\x90\x90\x90"			// 返回start
							; 

#define RELJMP 	11

int main(int argc, char* argv[]) 
{
	int fd, i;
	char rdbuf[MAX];
	char* rp;

	unsigned char* base;
	unsigned int size, * off, offs;
	unsigned long stub, orig;
	unsigned long clen = sizeof(stub_code) - 1;	// 除去最后一个'\0'
	Elf32_Ehdr* ehdr;
	Elf32_Phdr* phdrs;
	// Elf32_Shdr* shdrs;

	// 这是一个e9 jmp rel32指令
	stub_code[RELJMP] = 0xe9;
	off = (unsigned int*) &stub_code[RELJMP + 1];
	
/*
	// __asm__ __volatile__("xchg %bx, %bx");
	fd = open(argv[1], O_RDWR);
	// __asm__ __volatile__("xchg %bx, %bx");
	// size = lseek(fd, 0, SEEK_END);
	// __asm__ __volatile__("xchg %bx, %bx");
	base = fd;
	// base = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);

	// __asm__ __volatile__("xchg %bx, %bx");
	ehdr = (Elf32_Ehdr*) base;
	phdrs = (Elf32_Phdr*) &base[ehdr->e_phoff];
	// shdrs = (Elf32_Shdr*) &base[ehdr->e_shoff];
	// orig = ehdr->e_entry;

	// 此处开始修改程序入口, 假设shellcode长0x20,则应放在0x1000 - 0x20 - 0x1处
	stub = 0xFF0;
	//__asm__ __volatile__("xchg %bx, %bx");
	/ehdr->e_entry = (Elf32_Addr)stub;				// 令程序段入口为elf头的填充区地址
	// __asm__ __volatile__("xchg %bx, %bx");
	// 修改phdr的offset为0xFF0, 最后bochs将根据这个offset加载文件代码
	phdrs->p_offset = (Elf32_Off)stub;

	// 此处开始填充代码
	// __asm__ __volatile__("xchg %bx, %bx");
	// write(fd, "aaaa", 4);
	memcpy(base + 0xFF0, stub_code, 11);
	memcpy(base + 0xFF0 + 0xb, "\x00", 1);
	memcpy(base + 0xFF0 + 0xb + 0x1, stub_code + 12, 4);


	// memcpy(0xd027ff0, stub_code, 16);


	// 此处开始修改程序头的文件大小
	// phdrs[0].p_filesz += clen;
	// phdrs[0].p_memsz += clen;


	// munmap(base, size);
*/

	fd = open(argv[1], O_RDWR);
	read(fd, rdbuf, 0x1020);			// 将前0x1000字节读入rdbuf
	close(fd);

	fd = open(argv[1], O_RDWR);			// 先将e_entry之前的部分原封不动的写回
	write(fd, rdbuf, 0x18);
	
	write(fd, "\xE8\x0F\x0\x0", 4);		// 修改e_entry为0x00 00 0F E8
	
	rp = rdbuf + 0x1c;
	write(fd, rp, 0x1c);				// 原封不动的写回e_entry,p_offset之间的部分
	
	write(fd, "\xE8\x0F\x0\x0", 4);		// 将p_offset改为0x00 00 0F E8
	
	rp = rdbuf + 0x3c;
	write(fd, rp, 0xFAC);				// 继续填充0xFE8 - 0x38 - 0x4个字节
	
	// 以下部分为shellcode填充
	write(fd, stub_code, 11);
	write(fd, "\x00", 1);
	write(fd, stub_code + 12, 4);
	write(fd, stub_code + 16, 3);
	write(fd, "\x00", 1);
	write(fd, stub_code + 20, 4);

	// 以下部分为使pwd正常工作，将push 0x1768 改为 0x1778
	write(fd, rdbuf + 0x1000, 0x14);
	write(fd, "\x68\x80", 2);
	
	close(fd);

	return 0;
}
