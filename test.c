#include "hmac_sha256.h"
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
    int input_size = 8;
    int output_size = -1;
    int error = 0;
    char* output;

    static char *messages[] =
    {
        "Hi There",
        "&TRE&1367409212"
    };
    output = g(messages[0], input_size, &error, &output_size);
    printf("Encryption is: %s ; size of result is %d \n", output, output_size);
}
