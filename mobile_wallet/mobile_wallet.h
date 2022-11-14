#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * Take a pointer to a NUL-terminated UTF8-string and return whether this is
 * a correct format for a concordium address.
 * A non-zero return value signals success.
 * #Safety
 * The input must be NUL-terminated.
 */
uint8_t check_account_address(const char *input_ptr);

/**
 * Take a pointer to two NUL-terminated UTF8-strings and return a
 * NUL-terminated UTF8-encoded string. The returned string must be freed by the
 * caller by calling the function 'free_response_string'. In case of failure
 * the function returns an error message as the response, and sets the
 * 'success' flag to 0.
 *
 * See rust-bins/wallet-notes/README.md for the description of input and output
 * formats.
 *
 * # Safety
 * The input pointer must point to a null-terminated buffer, otherwise this
 * function will fail in unspecified ways.
 */
char *combine_encrypted_amounts(const char *input_ptr_1, const char *input_ptr_2, uint8_t *success);

/**
 * # Safety
 * The input pointer must point to a null-terminated buffer, otherwise this
 * function will fail in unspecified ways.
 */
char *generate_accounts(const char *input_ptr, uint8_t *success);

/**
 * # Safety
 * The input pointer must point to a null-terminated buffer, otherwise this
 * function will fail in unspecified ways.
 */
char *generate_accounts_v1(const char *input_ptr, uint8_t *success);

/**
 * # Safety
 * The input pointer must point to a null-terminated buffer, otherwise this
 * function will fail in unspecified ways.
 */
char *create_credential(const char *input_ptr, uint8_t *success);

/**
 * # Safety
 * The input pointer must point to a null-terminated buffer, otherwise this
 * function will fail in unspecified ways.
 */
char *create_credential_v1(const char *input_ptr, uint8_t *success);

/**
 * Take a pointer to a NUL-terminated UTF8-string and return a NUL-terminated
 * UTF8-encoded string. The returned string must be freed by the caller by
 * calling the function 'free_response_string'. In case of failure the function
 * returns an error message as the response, and sets the 'success' flag to 0.
 *
 * See rust-bins/wallet-notes/README.md for the description of input and output
 * formats.
 *
 * # Safety
 * The input pointer must point to a null-terminated buffer, otherwise this
 * function will fail in unspecified ways.
 */
char *create_encrypted_transfer(const char *input_ptr, uint8_t *success);

/**
 * # Safety
 * The input pointer must point to a null-terminated buffer, otherwise this
 * function will fail in unspecified ways.
 */
char *create_id_request_and_private_data(const char *input_ptr, uint8_t *success);

/**
 * # Safety
 * The input pointer must point to a null-terminated buffer, otherwise this
 * function will fail in unspecified ways.
 */
char *create_id_request_and_private_data_v1(const char *input_ptr, uint8_t *success);

/**
 * # Safety
 * The input pointer must point to a null-terminated buffer, otherwise this
 * function will fail in unspecified ways.
 */
char *generate_recovery_request(const char *input_ptr, uint8_t *success);

/**
 * # Safety
 * The input pointer must point to a null-terminated buffer, otherwise this
 * function will fail in unspecified ways.
 */
char *prove_id_statement(const char *input_ptr, uint8_t *success);

/**
 * Take a pointer to a NUL-terminated UTF8-string and return a NUL-terminated
 * UTF8-encoded string. The returned string must be freed by the caller by
 * calling the function 'free_response_string'. In case of failure the function
 * returns an error message as the response, and sets the 'success' flag to 0.
 *
 * See rust-bins/wallet-notes/README.md for the description of input and output
 * formats.
 *
 * # Safety
 * The input pointer must point to a null-terminated buffer, otherwise this
 * function will fail in unspecified ways.
 */
char *create_pub_to_sec_transfer(const char *input_ptr, uint8_t *success);

/**
 * Take a pointer to a NUL-terminated UTF8-string and return a NUL-terminated
 * UTF8-encoded string. The returned string must be freed by the caller by
 * calling the function 'free_response_string'. In case of failure the function
 * returns an error message as the response, and sets the 'success' flag to 0.
 *
 * See rust-bins/wallet-notes/README.md for the description of input and output
 * formats.
 *
 * # Safety
 * The input pointer must point to a null-terminated buffer, otherwise this
 * function will fail in unspecified ways.
 */
char *create_sec_to_pub_transfer(const char *input_ptr, uint8_t *success);

/**
 * Take a pointer to a NUL-terminated UTF8-string and return a NUL-terminated
 * UTF8-encoded string. The returned string must be freed by the caller by
 * calling the function 'free_response_string'. In case of failure the function
 * returns an error message as the response, and sets the 'success' flag to 0.
 *
 * See rust-bins/wallet-notes/README.md for the description of input and output
 * formats.
 *
 * # Safety
 * The input pointer must point to a null-terminated buffer, otherwise this
 * function will fail in unspecified ways.
 */
char *create_transfer(const char *input_ptr, uint8_t *success);

/**
 * Take a pointer to a NUL-terminated UTF8-string and return a NUL-terminated
 * UTF8-encoded string. The returned string must be freed by the caller by
 * calling the function 'free_response_string'. In case of failure the function
 * returns an error message as the response, and sets the 'success' flag to 0.
 *
 * See rust-bins/wallet-notes/README.md for the description of input and output
 * formats.
 *
 * # Safety
 * The input pointer must point to a null-terminated buffer, otherwise this
 * function will fail in unspecified ways.
 */
char *create_configure_delegation_transaction(const char *input_ptr, uint8_t *success);

/**
 * Take a pointer to a NUL-terminated UTF8-string and return a NUL-terminated
 * UTF8-encoded string. The returned string must be freed by the caller by
 * calling the function 'free_response_string'. In case of failure the function
 * returns an error message as the response, and sets the 'success' flag to 0.
 *
 * See rust-bins/wallet-notes/README.md for the description of input and output
 * formats.
 *
 * # Safety
 * The input pointer must point to a null-terminated buffer, otherwise this
 * function will fail in unspecified ways.
 */
char *create_configure_baker_transaction(const char *input_ptr, uint8_t *success);

/**
 * Return a NUL-terminated UTF8-encoded string.The returned string must be freed
 * by the caller by calling the function 'free_response_string'. In case of
 * failure the function returns an error message as the response, and sets the
 * 'success' flag to 0.
 *
 * See rust-bins/wallet-notes/README.md for the description of output
 * formats.
 */
char *generate_baker_keys(uint8_t *success);

/**
 * Take a pointer to a NUL-terminated UTF8-string and return a NUL-terminated
 * UTF8-encoded string. The returned string must be freed by the caller by
 * calling the function 'free_response_string'. In case of failure the function
 * returns an error message as the response, and sets the 'success' flag to 0.
 *
 * See rust-bins/wallet-notes/README.md for the description of input and output
 * formats.
 *
 * # Safety
 * The input pointer must point to a null-terminated buffer, otherwise this
 * function will fail in unspecified ways.
 */
uint64_t decrypt_encrypted_amount(const char *input_ptr, uint8_t *success);

/**
 * Take a pointer to a NUL-terminated UTF8-string and return a NUL-terminated
 * UTF8-encoded string. The returned string must be freed by the caller by
 * calling the function 'free_response_string'. In case of failure the function
 * returns an error message as the response, and sets the 'success' flag to 0.
 *
 * See rust-bins/wallet-notes/README.md for the description of input and output
 * formats.
 *
 * # Safety
 * The input pointer must point to a null-terminated buffer, otherwise this
 * function will fail in unspecified ways.
 */
char *get_identity_keys_and_randomness(const char *input_ptr, uint8_t *success);

/**
 * Take a pointer to a NUL-terminated UTF8-string and return a NUL-terminated
 * UTF8-encoded string. The returned string must be freed by the caller by
 * calling the function 'free_response_string'. In case of failure the function
 * returns an error message as the response, and sets the 'success' flag to 0.
 *
 * See rust-bins/wallet-notes/README.md for the description of input and output
 * formats.
 *
 * # Safety
 * The input pointer must point to a null-terminated buffer, otherwise this
 * function will fail in unspecified ways.
 */
char *get_account_keys_and_randomness(const char *input_ptr, uint8_t *success);

/**
 * Take a pointer to a NUL-terminated UTF8-string and return a NUL-terminated
 * UTF8-encoded string. The returned string must be freed by the caller by
 * calling the function 'free_response_string'. In case of failure the function
 * returns an error message as the response, and sets the 'success' flag to 0.
 *
 * See rust-bins/wallet-notes/README.md for the description of input and output
 * formats.
 *
 * # Safety
 * The input pointer must point to a null-terminated buffer, otherwise this
 * function will fail in unspecified ways.
 */
char *parameter_to_json(const char *input_ptr, uint8_t *success);

/**
 * Take a pointer to a NUL-terminated UTF8-string and return a NUL-terminated
 * UTF8-encoded string. The returned string must be freed by the caller by
 * calling the function 'free_response_string'. In case of failure the function
 * returns an error message as the response, and sets the 'success' flag to 0.
 *
 * See rust-bins/wallet-notes/README.md for the description of input and output
 * formats.
 *
 * # Safety
 * The input pointer must point to a null-terminated buffer, otherwise this
 * function will fail in unspecified ways.
 */
char *create_account_transaction(const char *input_ptr, uint8_t *success);

/**
 * Take a pointer to a NUL-terminated UTF8-string and return a NUL-terminated
 * UTF8-encoded string. The returned string must be freed by the caller by
 * calling the function 'free_response_string'. In case of failure the function
 * returns an error message as the response, and sets the 'success' flag to 0.
 *
 * See rust-bins/wallet-notes/README.md for the description of input and output
 * formats.
 *
 * # Safety
 * The input pointer must point to a null-terminated buffer, otherwise this
 * function will fail in unspecified ways.
 */
char *sign_message(const char *input_ptr, uint8_t *success);

/**
 * Take a pointer to a NUL-terminated UTF8-string and return a NUL-terminated
 * UTF8-encoded string. The returned string must be freed by the caller by
 * calling the function 'free_response_string'. In case of failure the function
 * returns an error message as the response, and sets the 'success' flag to 0.
 *
 * See rust-bins/wallet-notes/README.md for the description of input and output
 * formats.
 *
 * # Safety
 * The input pointer must point to a null-terminated buffer, otherwise this
 * function will fail in unspecified ways.
 */
char *serialize_token_transfer_parameters(const char *input_ptr, uint8_t *success);

/**
 * # Safety
 * This function is unsafe in the sense that if the argument pointer was not
 * Constructed via CString::into_raw its behaviour is undefined.
 */
void free_response_string(char *ptr);
