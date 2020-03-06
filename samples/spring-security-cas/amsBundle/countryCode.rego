package rbac

import data.user2policy as u2p

# DEFINE POLICY CountryCode {
#    GRANT RULE WHERE Country = "DE" OR Country = "FR";
# }
countryCode {
    u2p[input.user][_] == "countryCode"
    values := ["DE", "FR"]
    input.Country == values[_]
}