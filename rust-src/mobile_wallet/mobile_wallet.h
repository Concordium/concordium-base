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
 * # Safety
 * This function is unsafe in the sense that if the argument pointer was not
 * Constructed via CString::into_raw its behaviour is undefined.
 */
void free_response_string(char *ptr);
