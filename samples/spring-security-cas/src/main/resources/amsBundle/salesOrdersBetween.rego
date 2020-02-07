package rbac

import data.user2policy as u2p

# DEFINE POLICY salesOrders {
#    GRANT RULE read WHERE Country = "DE" AND SalesID BETWEEN (100,200)
# }
salesOrdersBetween {
    u2p[input.user][_] == "salesOrdersBetween"
    input.action == "read"
    input.Country == "DE"
    input.SalesID >= 100
    input.SalesID <= 200
}