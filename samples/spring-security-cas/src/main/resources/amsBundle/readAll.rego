package rbac

import data.user2policy as u2p

# DEFINE POLICY readAll {
#     GRANT RULE read;
# }
readAll {
    u2p[input.user][_] == "readAll"
    input.action == "read"
}