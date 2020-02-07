package rbac

import data.user2policy as u2p

# DEFINE POLICY salesOrders {
#    GRANT RULE read WHERE Country = "DE"
# }
salesOrders {
    u2p[input.user][_] == "salesOrders"
    input.action == "read"
    input.Country == "DE"
}