#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <asm/types.h>
#include <linux/net.h>
#include <stdint.h>
#include <string.h>

#include "extension/extension.h"
#include "tracee/tracee.h"
#include "tracee/mem.h"

#define X_AF_NETLINK 16
#define X_NETLINK_AUDIT 9

int audit_log_callback(Extension *extension, ExtensionEvent event, intptr_t data1 UNUSED, intptr_t data2 UNUSED) {
    switch (event) {
    case INITIALIZATION: {
        static FilteredSysnum filtered_sysnums[] = {
            { PR_socket, FILTER_SYSEXIT },
            FILTERED_SYSNUM_END
        };
        extension->filtered_sysnums = filtered_sysnums;
        return 0;
    }

    case SYSCALL_ENTER_END: {
        Tracee *tracee = TRACEE(extension);
        switch(get_sysnum(tracee, ORIGINAL)) {
            case PR_socket: {
                /* Unconditionally emulate audit not in kernel. */
                int arg1 = peek_reg(tracee, ORIGINAL, SYSARG_1);
                int arg2 = peek_reg(tracee, ORIGINAL, SYSARG_3);
                if (arg1 == X_AF_NETLINK && arg2 == X_NETLINK_AUDIT) {
                    return -EPROTONOSUPPORT;
                }
                return 0;
            }
            default:
                return 0;
        }
    }

    default:
        return 0;
    }
}
