#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>

char* create_id_request_and_private_data_ext(char*, uint8_t*);
char* create_credential_ext(char*, uint8_t*);
uint8_t check_account_address_ext(char*);

char* create_transfer_ext(char*, uint8_t*);

char* create_encrypted_transfer_ext(char*, uint8_t*); //
char* combine_encrypted_amounts_ext(char*, char*, uint8_t*);
uint64_t decrypt_encrypted_amount_ext(char*, uint8_t*);

void free_response_string_ext(char*);

char* create_encrypted_amount_ext(char*, uint8_t*);

/*
$ ./example create_transfer-input.json
  calls create_transfer_ext with the contents of create_transfer-input.json

$ ./example create_id_request_and_private_data-input.json
  calls create_id_request_and_private_data_ext with the contents of create_id_request_and_private_data-input.json.

$ ./example create_credential-input.json
  calls create_credential_ext with the contents of create_credential-input.json.

$ ./example create_encrypted_transfer-input.json
  calls create_encrypted_transfer_ext with with the contents of create_encrypted_transfer-input.json

$ ./example combine-amounts <encryptedAmount1> <encryptedAmount2>
  calls combine_encrypted_amounts_ext with the two amounts

$ ./example decrypt_encrypted_amount-input.json
  calls decrypt_encrypted_amount_ext with the contents of decrypt_encrypted_amount-input.json

$ ./example check-address <address>
  calls check_account_address_ext with the given address
*/

void printStr(char *out, uint8_t flag) {
  if (flag) {
    printf("%s\n", out);
  } else {
    fprintf(stderr, "Failure.\n");
    fprintf(stderr, "%s\n", out);
  }
  free_response_string_ext(out);
}

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
      uint64_t decrypted;
      if (strcmp(argv[1], "create_transfer-input.json") == 0) {
        out = create_transfer_ext(buffer, &flag);
        printStr(out, flag);
      } else if (strcmp(argv[1], "create_id_request_and_private_data-input.json") == 0) {
        out = create_id_request_and_private_data_ext(buffer, &flag);
        printStr(out, flag);
      } else if (strcmp(argv[1], "create_credential-input.json") == 0) {
        out = create_credential_ext(buffer, &flag);
        printStr(out, flag);
      } else if (strcmp(argv[1], "create_encrypted_transfer-input.json") == 0) {
        out = create_encrypted_transfer_ext(buffer, &flag);
        printStr(out, flag);
      } else if (strcmp(argv[1], "create_encrypted_amount-input2.json") == 0) {
        out = create_encrypted_amount_ext(buffer, &flag);
        printStr(out, flag);
      } else if (strcmp(argv[1], "decrypt_encrypted_amount-input2.json") == 0) {
        decrypted = decrypt_encrypted_amount_ext(buffer, &flag);
        if (flag) {
          printf("Decrypted amount: %" PRIu64 "\n", decrypted);
        } else {
          fprintf(stderr, "Failure.\n");
        }
      }
    }

  } else {
    if (strcmp(argv[1], "check-address") == 0) {
      if (check_account_address_ext(argv[2])) {
        printf("Account address valid.\n");
      } else {
        printf("Account address invalid.\n");
      }
    } else if (strcmp(argv[1], "combine-amounts") == 0) {
      uint8_t flag = 1;
      char *out;
      out = combine_encrypted_amounts_ext(argv[2], argv[3], &flag);
      printf("%s\n", out);
    }
  }
  return 0;
}
