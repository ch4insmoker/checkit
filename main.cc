#include "checkelf.h"
#include "checkpe.h"


// TODO:
// Stack canaries

int main(int argc, char **argv) {
    
    FILE *fp;
    uint32_t sig;
    if (argc < 2 || (fp = fopen(argv[1], "rb")) == NULL) {
        fputs("./check_it <file>\n", stderr); 
        exit(-1);
    }

    fread(&sig, 4, 1, fp);
    if ((uint16_t)sig == chk_IMAGE_DOS_SIGNATURE) {
        checkpe(fp);
    } else if (sig == 0x464c457f){
        checkelf(fp);
    } else {
        fputs("invalid file format!\n", stderr);
    }

    fclose(fp);
}