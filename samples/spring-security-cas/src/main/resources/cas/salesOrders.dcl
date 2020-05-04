schema {
		salesID: Number,
		CountryCode: String,
        $user: {
            "name": string,
             country: string,
            "PersNumber": Number
        }
}

POLICY readAll {
	GRANT read ON *;
}

POLICY readWrite {
	GRANT read, write ON *;
}

POLICY countryCode {
	GRANT read ON * WHERE CountryCode = 'IT';
}

POLICY salesOrders2 {
	GRANT read, write, delete, activate ON salesOrders;
}

POLICY adminAll {
	GRANT admin ON *;
}

POLICY salesOrdersBetween {
	GRANT read, write, delete ON salesOrders WHERE salesID BETWEEN 100 AND 500;
}

POLICY salesOrdersLT {
	GRANT read ON salesOrders WHERE salesID <= 700;
}