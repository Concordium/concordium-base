#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>

char* create_id_request_and_private_data_ext(char*, uint8_t*);
char* create_credential_ext(char*, uint8_t*);
char* generate_accounts_ext(char*, uint8_t*);
uint8_t check_account_address_ext(char*);

char* create_transfer_ext(char*, uint8_t*);

char* create_encrypted_transfer_ext(char*, uint8_t*); //
char* combine_encrypted_amounts_ext(char*, char*, uint8_t*);
uint64_t decrypt_encrypted_amount_ext(char*, uint8_t*);

char* create_pub_to_sec_transfer_ext(char*, uint8_t*);
char* create_sec_to_pub_transfer_ext(char*, uint8_t*);

void free_response_string_ext(char*);

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

int printStr(char *out, uint8_t flag) {
  int r = 0;
  if (flag) {
    printf("%s\n", out);
  } else {
    fprintf(stderr, "Failure.\n");
    fprintf(stderr, "%s\n", out);
    r = 1;
  }
  free_response_string_ext(out);
  return r;
}

// check if the second string is a suffix of the first one.
int ends_with(const char* str, const char* suffix) {
  if (str == NULL || suffix == NULL) {
    return 0;
  }
  size_t l = strlen(str);
  size_t ls = strlen(suffix);
  if (ls > l) {
      return 0;
  }
  int cmp = strcmp(str + (l - ls), suffix);
  return cmp == 0 ? 1 : 0;
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
      if (ends_with(argv[1], "create_transfer-input.json")) {
        out = create_transfer_ext(buffer, &flag);
        return printStr(out, flag);
      } else if (ends_with(argv[1], "create_id_request_and_private_data-input.json")) {
        out = create_id_request_and_private_data_ext(buffer, &flag);
        return printStr(out, flag);
      } else if (ends_with(argv[1], "create_credential-input.json")) {
        out = create_credential_ext(buffer, &flag);
        return printStr(out, flag);
      } else if (ends_with(argv[1], "generate-accounts-input.json")) {
        out = generate_accounts_ext(buffer, &flag);
        return printStr(out, flag);
      } else if (ends_with(argv[1], "create_encrypted_transfer-input.json")) {
        out = create_encrypted_transfer_ext(buffer, &flag);
        return printStr(out, flag);
      } else if (ends_with(argv[1], "create_pub_to_sec_transfer-input.json")) {
        out = create_pub_to_sec_transfer_ext(buffer, &flag);
        return printStr(out, flag);
      } else if (ends_with(argv[1], "create_sec_to_pub_transfer-input.json")) {
        out = create_sec_to_pub_transfer_ext(buffer, &flag);
        return printStr(out, flag);
      } else if (ends_with(argv[1], "decrypt_encrypted_amount-input.json")) {
        decrypted = decrypt_encrypted_amount_ext(buffer, &flag);
        if (flag) {
          printf("Decrypted amount: %" PRIu64 "\n", decrypted);
          return 0;
        } else {
          fprintf(stderr, "Failure.\n");
          return 1;
        }
      } else {
        printf("Unrecognized option.");
        return 1;
      }
    }
  } else {
    if (strcmp(argv[1], "check-address") == 0) {
      if (check_account_address_ext(argv[2])) {
        printf("Account address valid.\n");
      } else {
        printf("Account address invalid.\n");
      }
      return 0;
    } else if (strcmp(argv[1], "combine-amounts") == 0) {
      uint8_t flag = 1;
      char *out;
      out = combine_encrypted_amounts_ext(argv[2], argv[3], &flag);
      printf("%s\n", out);
      return (int)flag;
    }
  }
}
