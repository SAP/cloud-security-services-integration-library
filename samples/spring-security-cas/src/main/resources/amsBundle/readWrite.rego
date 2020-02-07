package rbac

import data.user2policy as u2p

# DEFINE POLICY readWrite {
#    GRANT RULE read, write;
# }
readWrite {
    u2p[input.user][_] == "readWrite"
    actions := ["read", "write"]
    input.action == actions[_]
}