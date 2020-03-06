package rbac

import data.user2policy as u2p

default allow = false


allow {
    readAll
}

allow {
    readWrite
}

allow {
    countryCode
}

allow {
    salesOrders
}

allow {
    salesOrdersIn
}

allow {
    salesOrdersBetween
}

allow {
    salesOrdersRes
}

allow {
    salesOrdersLike
}

