package rbac

import data.user2policy as u2p

# DEFINE POLICY salesOrdersLike {
#    GRANT RULE read ON SalesOrders WHERE Name LIKE "*Deal*"    
# }
salesOrdersLike {
    u2p[input.user][_] == "salesOrdersLike"
    input.action == "read"
    input.resource == "SalesOrders"
    glob.match( "*Deal*", [], input.Name) 
}