#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>
#include <time.h>

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

#define ELF_MAGIC 0x7F454C46 //0x7FELF
#define PE_SIG 0x00004550 // PE
#define THREAD_COUNT 5

pthread_mutex_t print_mutex = PTHREAD_MUTEX_INITIALIZER;

void print_elf_info(Elf32_Ehdr *elf_header){
	while(!pthread_mutex_trylock(&print_mutex));
	printf("Elf File detected.\n");
	printf("Entry point: 0x%x\n", elf_header->e_entry);
	pthread_mutex_unlock(&print_mutex);
}
void print_pe_info(PE_Header *pe_header){
	while(!pthread_mutex_trylock(&print_mutex));
	printf("PE file detected.\n");
	printf("Number of Sections: %d\n", pe_header->numberOfSections);
	pthread_mutex_unlock(&print_mutex);
}

int identify(char *filename){
	FILE *file = fopen(filename, "rb");
	if (!file){
		perror("Error opening file");
		return 1;
	}

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
		//uint32_t ehmagic = *(uint32_t*)elf_header.e_ident;
		//ehmagic = (ehmagic >> 24) | ((ehmagic >> 8) & 0x0000FF00) | ((ehmagic << 8) & 0x00FF0000) | (ehmagic << 24);
		//printf("Elf Magic: 0x%08x\n", ehmagic);
		print_elf_info(&elf_header);
	}
	else if (magic[0] == 0x4D && magic[1] == 0x5A){
		fseek(file, 0x3C, SEEK_SET);
		uint32_t pe_header_offset;
		fread(&pe_header_offset, sizeof(uint32_t), 1, file);

		fseek(file, pe_header_offset, SEEK_SET);
		PE_Header pe_header;
		fread(&pe_header, sizeof(PE_Header), 1, file);
		print_pe_info(&pe_header);
	}
	else {
		fprintf(stderr, "Unknown file format\n");
		fclose(file);
		return 1;
	}
	fclose(file);
	return 0;
}
// change threads to have a waitlist if >5 are need
// print -> rewrite to a buffer. use snprintf buffer of 32 bytes -> fputs of the buffer to stdout lock the fputs not the snprintf
// add timers for funsies
int main(int argc, char *argv[]){
	clock_t start_time, end_time;
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
		//name file file file file file
		pthread_t tid[THREAD_COUNT];
		for(int i = 0; i<argc-1; i++){
			pthread_create(&tid[i], NULL, identify, argv[i+1]);
		}
		for(int i = 0; i<argc-1;i++){
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
