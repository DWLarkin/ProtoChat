#include "protochat.h"

#include <stdio.h>
#include <stdlib.h>

int main(void) {
    pstate_t proto_state = {0};
    proto_state.connfd = -1;

    if (0 != proto_setup(&proto_state)) {
        return EXIT_SUCCESS;
    }

    run_client(&proto_state);

    return EXIT_SUCCESS;
}
