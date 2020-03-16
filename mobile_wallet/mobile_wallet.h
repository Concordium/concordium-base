#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

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
char *create_id_request_and_private_data(const char *input_ptr, uint8_t *success);

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
 * # Safety
 * This function is unsafe in the sense that if the argument pointer was not
 * Constructed via CString::into_raw its behaviour is undefined.
 */
void free_response_string(char *ptr);
