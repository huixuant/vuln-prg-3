#include <stdlib.h>
#include <Windows.h>
#include <io.h>
#include <fcntl.h>
#include <sys\stat.h>
#include <share.h>
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
    int fd;
    __int64 file_size;
    int bytes_read;

    _sopen_s(&fd, filename, _O_RDONLY, _SH_DENYRW, _S_IREAD);
    if (fd == -1) {
        fputs("Error opening file.", stderr);
        return 0;
    }

    file_size = _filelengthi64(fd);
    if (file_size == -1) {
        fputs("Error getting file size.", stderr);
        return 0;
    }

    // dynamically allocate memory for file data
    unsigned char* buf = malloc(sizeof(unsigned char) * (file_size + 1));
    if (buf == NULL) {
        fputs("Memory error occured.", stderr);
        return 0;
    }

    memset(buf, 0, sizeof(unsigned char) * (file_size + 1));
    if ((bytes_read = _read(fd, buf, file_size)) <= 0) {
        fputs("Problem reading file.", stderr);
        return 0;
    }
  
    _close(fd);

    uint32_t computed_crc = rc_crc32(0, buf, file_size);
    
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