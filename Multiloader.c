#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>
#include <time.h>

#define THREAD_COUNT 2

//Elf
typedef struct {
	unsigned char e_ident[16]; // ID bytes, magic number + more
	uint16_t e_type; 	    // Type of Elf file
	uint16_t e_machine;	    // Machine Architecture
	uint32_t e_version;	    // ELF Version -> EV_CURRENT = 1
	uint32_t e_entry;	    // Entry Point Address
	uint32_t e_phoff;	    // Program Header Table Offset
	uint32_t e_shoff;	    // Section Header Table Offset
	uint32_t e_flags;	    // Processor Specific Flags
	uint16_t e_ehsize;	    // ELF header size (bytes)
	uint16_t e_phentsize;	    // Size of Program Header Table (bytes)
	uint16_t e_phnum;	    // Number of Program Header Table Entries
	uint16_t e_shentsize;	    // Size of Section Header Table (bytes)
	uint16_t e_shnum;	    // Number of Program Header Table Entries
	uint16_t e_shstrndx;	    // Index of Section Header string table
} Elf32_Ehdr;

//Section
typedef struct {
	uint32_t sh_name;
	uint32_t sh_type;
	uint32_t sh_flags;
	uint32_t sh_addr;
	uint32_t sh_offset;
	uint32_t sh_size;
	uint32_t sh_link;
	uint32_t sh_info;
	uint32_t sh_addralign;
	uint32_t sh_entsize;
} Elf32_Shdr;

//PE
typedef struct {
	uint32_t signature;
	uint16_t machine;
	uint16_t numberOfSections;
	uint32_t timeDateStamp;
	uint32_t pointToSymbolTable;
	uint32_t numberOfSymbols;
	uint16_t sizeOfOptionalHeader;
	uint16_t characteristics;
} PE_Header;
typedef struct {
	uint32_t Signature;
	PE_Header Fileheader;
} PE_FILE;
typedef struct {
	uint16_t e_magic;
	uint16_t e_cblp;
	uint16_t e_cp;
	uint16_t e_crlc;
	uint16_t e_cparhdr;
	uint16_t e_minalloc;
	uint16_t e_maxalloc;
	uint16_t e_ss;
	uint16_t e_sp;
	uint16_t e_csum;
	uint16_t e_ip;
	uint16_t e_cs;
	uint16_t e_lfarlc;
	uint16_t e_ovno;
	uint16_t e_res[4];
	uint16_t e_oeminfo;
	uint16_t e_res2[10];
	uint32_t e_lfanew;
} IMAGE_DOS_HEADER;
typedef struct {
	char Name[8];
	uint32_t VirtualSize;
	uint32_t VirtualAddress;
	uint32_t SizeOfRawData;
	uint32_t PointerToRawData;
	uint32_t PointerToRelocations;
	uint32_t PointerToLinenumbers;
	uint16_t NumberOfRelocations;
	uint16_t NumberOfLinenumbers;
	uint32_t Characteristics;
} IMAGE_SECTION_HEADER;

pthread_mutex_t print_mutex = PTHREAD_MUTEX_INITIALIZER;

void print_elf_info(Elf32_Ehdr *elf_header){
	char buf[256];
	int result = snprintf(buf, sizeof(buf), "Elf File Detected.\n"
			"Entry Point: 0x%x\n", elf_header->e_entry);
	while(!pthread_mutex_trylock(&print_mutex));
	fputs(buf, stdout);
	pthread_mutex_unlock(&print_mutex);
}
void print_pe_info(PE_Header *pe_header){
	char buf[256];
	int result = snprintf(buf, sizeof(buf), "PE File Detected.\n"
			"Number of Sections: %d\n", pe_header->numberOfSections);
	while(!pthread_mutex_trylock(&print_mutex));
	fputs(buf, stdout);
	pthread_mutex_unlock(&print_mutex);
}
void print_elf_info_slow(Elf32_Ehdr *elf_header){
	while(!pthread_mutex_trylock(&print_mutex));
	printf("Elf File Detected.\n");
	printf("Entry Point: 0x%x\n", elf_header->e_entry);
	pthread_mutex_unlock(&print_mutex);
}
void print_pe_info_slow(PE_Header *pe_header){
	while(!pthread_mutex_trylock(&print_mutex));
	printf("PE File Detected.\n");
	printf("Number of Sections: %d\n", pe_header->numberOfSections);
	pthread_mutex_unlock(&print_mutex);
}
int strip_symbols_elf(char *filename){
	FILE *f = fopen(filename, "r+b");
	if(!f){
		perror("Error opening file to strip.\n");
		return 1;
	}
	Elf32_Ehdr ehdr;
	Elf32_Shdr shstrtab_hdr;
	fread(&ehdr, sizeof(ehdr), 1, f);
	if(ehdr.e_ident[0] != 0x7f || memcmp(&ehdr.e_ident[1], "ELF", 3) !=0){
		perror("Not an Elf File.\n");
		fclose(f);
		return 1;
	}
	fseek(f, ehdr.e_shoff + ehdr.e_shstrndx * sizeof(Elf32_Shdr), SEEK_SET);
	fread(&shstrtab_hdr, sizeof(shstrtab_hdr), 1, f);
	char *shstrtab = malloc(shstrtab_hdr.sh_size);
	fseek(f, shstrtab_hdr.sh_offset, SEEK_SET);
	fread(shstrtab, shstrtab_hdr.sh_size, 1, f);

	fseek(f, ehdr.e_shoff, SEEK_SET);
	for (int i = 0; i < ehdr.e_shnum; i++){
		Elf32_Shdr shdr;
		fread(&shdr, sizeof(shdr), 1, f);
		const char* name = shstrtab + shdr.sh_name;
		printf("Section %d Name %s Offset 0x%x Type 0x%x Size 0x%x \n", i, name, shdr.sh_offset, shdr.sh_type, shdr.sh_size);

		if(shdr.sh_type == 2 || shdr.sh_type == 11 || shdr.sh_type == 3 || shdr.sh_type == 0x6){
			printf("Found Section: %s (Type: %u) at offset: 0x%x, size 0x%x.\n",
					name, shdr.sh_type, shdr.sh_offset, shdr.sh_size);
			fseek(f, shdr.sh_offset, SEEK_SET);
			char *zero = calloc(1, shdr.sh_size);
			fwrite(zero, shdr.sh_size, 1, f);
			free(zero);
			//printf("File pointer after stripping section %d 0x%lx\n", i, ftell(f));
		}
		if (i < ehdr.e_shnum - 1){
			fseek(f, ehdr.e_shoff + (i+1) * sizeof(Elf32_Shdr), SEEK_SET);
		}
	}
	free(shstrtab);
	fclose(f);
	return 0;
}
int strip_symbols_pe(char *filename){
	FILE *f = fopen(filename, "r+b");
	if(!f){
		perror("Error opening file for stripping.\n");
		return 1;
	}
	IMAGE_DOS_HEADER dosHeader;
	fread(&dosHeader, sizeof(dosHeader), 1, f);
	printf("e_lfanew: 0x%lx\n", dosHeader.e_lfanew);
	fseek(f, dosHeader.e_lfanew, SEEK_SET);

	PE_FILE peFile;
	fread(&peFile, sizeof(peFile), 1, f);
	printf("Number of sections: %d\n", peFile.Fileheader.numberOfSections);

	IMAGE_SECTION_HEADER sectionHeader;
	fseek(f, dosHeader.e_lfanew + sizeof(PE_FILE), SEEK_SET);

	for(int i = 0; i < peFile.Fileheader.numberOfSections; i++){
		fread(&sectionHeader, sizeof(sectionHeader), 1, f);
		char sectionName[9];
		strncpy(sectionName, sectionHeader.Name, 8);
		sectionName[8] = '\0';
		printf("Section %d Name %s Virtual Size 0x%x Virtual Address 0x%x Size of Raw Data 0x%x\n",
				i, sectionName,sectionHeader.VirtualSize, sectionHeader.VirtualAddress,
				sectionHeader.SizeOfRawData);
		if(strstr(sectionName, ".data") || strstr(sectionName, ".rdata") || 
				strstr(sectionName, ".idata") || strstr(sectionName, ".pdata") ||
				strstr(sectionName, ".text") || strstr(sectionName, ".debug")){
			fseek(f, sectionHeader.PointerToRawData, SEEK_SET);
			char *zero = calloc(1, sectionHeader.SizeOfRawData);
			fwrite(zero, sectionHeader.SizeOfRawData, 1, f);
			free(zero);
			printf("File pointer after stripping section %d: 0x%lx\n", i, ftell(f));
		}
	}
	fclose(f);
}

int identify(char *filename){
	FILE *file = fopen(filename, "rb");
	if (!file){
		perror("Error opening file");
		return 1;
	}
	clock_t pstart, pend;
	double time;
	unsigned char magic[4];
	fread(magic, 1, 4, file);
	/*
	for (int i = 0; i<4; i++){
		printf("Magic Byte: %d: 0x%02X\n", i, magic[i]);
	}
	*/
	if (magic[0] == 0x7F && magic[1] == 0x45 &&
			magic[2] == 0x4C && magic[3] == 0x46){
		Elf32_Ehdr elf_header;
		fseek(file, 0, SEEK_SET);
		fread(&elf_header, sizeof(Elf32_Ehdr), 1, file);
		pstart = clock();
		print_elf_info(&elf_header);
		pend = clock();
		time = ((double)(pend-pstart));
		printf("regular print elf info: %f\n", time);
		pstart = clock();
		print_elf_info_slow(&elf_header);
		pend = clock();
		time = ((double)(pend-pstart));
		printf("slow print elf info: %f\n", time);
		pstart = clock();
		strip_symbols_elf(filename);
		pend = clock();
		time = ((double)(pend-pstart));
		printf("Time to strip sym tab: %f\n", time);
	}
	else if (magic[0] == 0x4D && magic[1] == 0x5A){
		fseek(file, 0x3C, SEEK_SET);
		uint32_t pe_header_offset;
		fread(&pe_header_offset, sizeof(uint32_t), 1, file);

		fseek(file, pe_header_offset, SEEK_SET);
		PE_Header pe_header;
		fread(&pe_header, sizeof(PE_Header), 1, file);
		pstart = clock();
		print_pe_info(&pe_header);
		pend = clock();
		time = ((double)(pend-pstart));
		printf("regular print pe info: %f\n", time);
		pstart = clock();
		print_pe_info_slow(&pe_header);
		pend = clock();
		time = ((double)(pend-pstart));
		printf("slow print pe info: %f\n", time);
		pstart = clock();
		strip_symbols_pe(filename);
		pend = clock();
		time = ((double)(pend-pstart));
		printf("Strip PE symbol time: %f\n", time);
	}
	else {
		fprintf(stderr, "Unknown file format\n");
		fclose(file);
		return 1;
	}
	fclose(file);
	return 0;
}
int main(int argc, char *argv[]){
	clock_t start_time, end_time, start_two, end_two;
	double time_taken;
	start_time = clock();
	if (argc < 2){
		printf("Standard Usage: ./loader ./<files to load>.\n");
		return 1;
	}
	else if (argc == 2){
		identify(argv[1]);
		return 0;
	}
	else{
		pthread_t tid[THREAD_COUNT];
		start_two = clock();
		for (int i = 0; i<argc-1; i++){
			if (i & 1 == 0){
			pthread_create(&tid[0], NULL, identify, argv[i+1]);
			}
			else {
			pthread_create(&tid[1], NULL, identify, argv[i+1]);
			}
		}
		end_two = clock();
		double time_two = ((double)(end_two - start_two));
		printf("Time for thread creation: %f\n", time_two);
		for(int i = 0; i<THREAD_COUNT;i++){
			pthread_join(tid[i], NULL);
		}
		
	}
	pthread_mutex_destroy(&print_mutex);
	end_time = clock();
	time_taken = ((double)(end_time-start_time));
	printf("Time taken: %f seconds for multithreaded runtime.\n", time_taken);
	start_time = clock();
	printf("Start time of linear run: %f\n", (double)start_time);
	for (int i = 0; i<argc; i++){
		identify(argv[i]);
	}
	end_time = clock();
	time_taken = ((double)(end_time-start_time));
	printf("Time taken: %f seconds for linear runtime.\n", time_taken);
	return 0;
}
