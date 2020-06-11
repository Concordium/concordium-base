#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

char* create_id_request_and_private_data_c(char*, uint8_t* );
char* create_credential_c(char*, uint8_t* );
char* create_transfer_c(char*, uint8_t* );
uint8_t check_account_address_c(char*);
void free_response_string_c(char*);

int main(int argc, char *argv[]) {
  char *buffer = 0;
  if (argc < 2) {
    fprintf(stderr, "You need to provide an input file.\n");
    return 1;
  }
  FILE *f = fopen(argv[1], "r");
  if (f) {
    fseek (f, 0, SEEK_END);
    long length = ftell(f);
    fseek (f, 0, SEEK_SET);
    buffer = malloc(length);
    if (buffer) {
      fread(buffer, 1, length, f);
    }
    fclose (f);
  
    if (buffer) {
      uint8_t flag = 1;
      char *out;
      // if input is named credential-cdi.json try to get the credential
      if (strcmp(argv[1], "credential-input.json") == 0) {
        out = create_credential_c(buffer, &flag);
      } else if (strcmp(argv[1], "transfer-input.json") == 0) {
        out = create_transfer_c(buffer, &flag);
      } else {
        out = create_id_request_and_private_data_c(buffer, &flag);
      } 
      if (flag) {
        printf("%s\n", out);
      } else {
        fprintf(stderr, "Failure.\n");
        fprintf(stderr, "%s\n", out);
      }
      free_response_string_c(out);
    }
  } else {
      if (check_account_address_c(argv[1])) {
        printf("Account address valid.\n");
      } else {
        printf("Account address invalid.\n");
      }
  }
  return 0;
}
