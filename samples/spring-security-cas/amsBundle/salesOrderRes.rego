package rbac

import data.user2policy as u2p

# DEFINE POLICY salesOrders {
#    GRANT RULE ON SalesOrders, SalesOrderItems, SalesOrderLists;
# }
salesOrdersRes {
    u2p[input.user][_] == "salesOrdersRes"
    input.action == "read"
    resources := ["SalesOrders", "SalesOrderItems", "SalesOrderLists"]
    input.resource == resources[_]
}