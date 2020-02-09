#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

char* create_id_request_and_private_data(char*, uint8_t* );
void free_response_string(char*);

int main() {
  char *buffer = 0;
  FILE *f = fopen("input.json", "r");
  if (f) {
    fseek (f, 0, SEEK_END);
    long length = ftell(f);
    fseek (f, 0, SEEK_SET);
    buffer = malloc(length);
    if (buffer) {
      fread(buffer, 1, length, f);
    }
    fclose (f);
  } else {
    fprintf(stderr, "Could not read input file.\n");
    return 1;
  }
  
  if (buffer) {
    uint8_t flag = 1;
    char *out = create_id_request_and_private_data(buffer, &flag);
    if (flag) {
      printf("%s\n", out);
    } else {
      fprintf(stderr, "Failure.");
      fprintf(stderr, "%s\n", out);
    }
  }
  return 0;
}
