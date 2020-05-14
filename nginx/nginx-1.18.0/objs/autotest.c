
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <sys/resource.h>
#include <inttypes.h>
#include "ngx_auto_config.h"

int main(void) {
    printf("%d", (int) sizeof(size_t));
    return 0;
}

