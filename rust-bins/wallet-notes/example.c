#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>

char* create_id_request_and_private_data(char*, uint8_t*);
char* create_credential(char*, uint8_t*);
char* create_id_request_and_private_data_v1(char*, uint8_t*);
char* create_credential_v1(char*, uint8_t*);
char* generate_recovery_request(char*, uint8_t*);
char* prove_id_statement(char*, uint8_t*);
char* generate_accounts(char*, uint8_t*);
uint8_t check_account_address(char*);

char* create_transfer(char*, uint8_t*);
char* create_configure_delegation_transaction(char*, uint8_t*);
char* create_configure_baker_transaction(char*, uint8_t*);
char* generate_baker_keys(uint8_t*);

char* create_encrypted_transfer(char*, uint8_t*); //
char* combine_encrypted_amounts(char*, char*, uint8_t*);
uint64_t decrypt_encrypted_amount(char*, uint8_t*);

char* create_pub_to_sec_transfer(char*, uint8_t*);
char* create_sec_to_pub_transfer(char*, uint8_t*);

void free_response_string(char*);

char* create_account_transaction(char*, uint8_t*);
char* parameter_to_json(char*, uint8_t*);
char* serialize_token_transfer_parameters(char*, uint8_t*);

/*
$ ./example create_transfer-input.json
  calls create_transfer with the contents of create_transfer-input.json

$ ./example create_id_request_and_private_data-input.json
  calls create_id_request_and_private_data with the contents of create_id_request_and_private_data-input.json.

$ ./example create_credential-input.json
  calls create_credential with the contents of create_credential-input.json.

$ ./example create_encrypted_transfer-input.json
  calls create_encrypted_transfer with with the contents of create_encrypted_transfer-input.json

$ ./example combine-amounts <encryptedAmount1> <encryptedAmount2>
  calls combine_encrypted_amounts with the two amounts

$ ./example decrypt_encrypted_amount-input.json
  calls decrypt_encrypted_amount with the contents of decrypt_encrypted_amount-input.json

$ ./example check-address <address>
  calls check_account_address with the given address
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
  free_response_string(out);
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
      if (ends_with(argv[1], "create_transfer-input.json") || ends_with(argv[1], "create_transfer_with_memo-input.json")) {
        out = create_transfer(buffer, &flag);
        return printStr(out, flag);
      } else if (ends_with(argv[1], "serialize_token_transfer_parameters-input.json")) {
          out = serialize_token_transfer_parameters(buffer, &flag);
          return printStr(out, flag);
      } else if (ends_with(argv[1], "parameter_to_json-input.json")) {
          out = parameter_to_json(buffer, &flag);
          return printStr(out, flag);
      } else if (ends_with(argv[1], "create_account_transaction-input.json")) {
          out = create_account_transaction(buffer, &flag);
          return printStr(out, flag);
      } else if (ends_with(argv[1], "create_id_request_and_private_data-input.json")) {
        out = create_id_request_and_private_data(buffer, &flag);
        return printStr(out, flag);
      } else if (ends_with(argv[1], "create_id_request_and_private_data-v1-input.json")) {
        out = create_id_request_and_private_data_v1(buffer, &flag);
        return printStr(out, flag);
      } else if (ends_with(argv[1], "create_credential-input.json")) {
        out = create_credential(buffer, &flag);
        return printStr(out, flag);
      } else if (ends_with(argv[1], "create_credential-v1-input.json")) {
        out = create_credential_v1(buffer, &flag);
        return printStr(out, flag);
      } else if (ends_with(argv[1], "generate-recovery-request-input.json")) {
        out = generate_recovery_request(buffer, &flag);
        return printStr(out, flag);
      } else if (ends_with(argv[1], "prove-id-statement-input.json")) {
        out = prove_id_statement(buffer, &flag);
        return printStr(out, flag);
      } else if (ends_with(argv[1], "create_configure_delegation_transaction-input.json")) {
        out = create_configure_delegation_transaction(buffer, &flag);
        return printStr(out, flag);
      } else if (ends_with(argv[1], "create_configure_baker_transaction-input.json")) {
        out = create_configure_baker_transaction(buffer, &flag);
        return printStr(out, flag);
      } else if (ends_with(argv[1], "generate-accounts-input.json")) {
        out = generate_accounts(buffer, &flag);
        return printStr(out, flag);
      } else if (ends_with(argv[1], "create_encrypted_transfer-input.json") || ends_with(argv[1], "create_encrypted_transfer_with_memo-input.json")) {
        out = create_encrypted_transfer(buffer, &flag);
        return printStr(out, flag);
      } else if (ends_with(argv[1], "create_pub_to_sec_transfer-input.json")) {
        out = create_pub_to_sec_transfer(buffer, &flag);
        return printStr(out, flag);
      } else if (ends_with(argv[1], "create_sec_to_pub_transfer-input.json")) {
        out = create_sec_to_pub_transfer(buffer, &flag);
        return printStr(out, flag);
      } else if (ends_with(argv[1], "decrypt_encrypted_amount-input.json")) {
        decrypted = decrypt_encrypted_amount(buffer, &flag);
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
      if (check_account_address(argv[2])) {
        printf("Account address valid.\n");
      } else {
        printf("Account address invalid.\n");
      }
      return 0;
    } else if (strcmp(argv[1], "combine-amounts") == 0) {
      uint8_t flag = 1;
      char *out;
      out = combine_encrypted_amounts(argv[2], argv[3], &flag);
      printf("%s\n", out);
      return (int)flag;
    } else if (strcmp(argv[1], "generate-baker-keys") == 0) {
      uint8_t flag = 1;
      char *out;
      out = generate_baker_keys(&flag);
      return printStr(out, flag);
    }
  }
}
