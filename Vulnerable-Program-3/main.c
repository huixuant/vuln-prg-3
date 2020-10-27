#include <stdlib.h>
#include <Windows.h>
#include "crc32.h"

#define MIN_REQ_SIZE 32

uint32_t crc = 0xd6c4dad7;

void this_is_a_vulnerable_function(size_t size) {
    char buf[10] = { 0 };
    buf[size] = "A";
}

int compare_crc(uint32_t a, uint32_t b) {
    if (a == b)
        return 1;
    else 
        return 0;
}

__declspec(dllexport) int fuzz_target(char* filename);

int fuzz_target(char* filename) {
    // open file 
    FILE* fp;
    errno_t err;
    err = fopen_s(&fp, filename, "r");
    if (err != 0) {
        printf("Error reading file.");
        return 0;
    }

    // determine no of bytes 
    fseek(fp, 0, SEEK_END);
    size_t bytes_count = ftell(fp);
    rewind(fp);

    // dynamically allocate memory for file data
    unsigned char* buf = malloc(sizeof(unsigned char) * (bytes_count + 1));
    if (buf == NULL) {
        fputs("Memory error occured.", stderr);
        return 0;
    }

    memset(buf, 0, sizeof(unsigned char) * (bytes_count + 1));
    fread(buf, sizeof(unsigned char), bytes_count, fp);
    fclose(fp);

    uint32_t computed_crc = rc_crc32(0, buf, bytes_count);
    
    if (compare_crc(computed_crc, crc))
        this_is_a_vulnerable_function(0xFFFF);
    else
        printf("Invalid input provided.");
    
    return 0;
}

int main(int argc, char* argv[]) {
	if (argc < 2) {
		printf("Usage: %s <input file>\n", argv[0]);
		return 0;
	}
	return fuzz_target(argv[1]);
}