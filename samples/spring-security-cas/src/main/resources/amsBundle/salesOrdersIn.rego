package rbac

import data.user2policy as u2p

#  DEFINE POLICY salesOrdersIn {
#     GRANT RULE read WHERE Country IN ("DE","IT")
# }
salesOrdersIn {
    u2p[input.user][_] == "saleOrdersIn"
    input.action == "read"
    values := ["DE", "IT"]
    input.Country == values[_]
}