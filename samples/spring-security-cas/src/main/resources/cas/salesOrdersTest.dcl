TEST salesOrdersLTTest {
    GRANT read ON salesOrders POLICY salesOrdersLT INPUT {
        salesID: -1
    }, {
        salesID: 700
    };

    DENY read ON salesOrders POLICY salesOrdersLT INPUT {
        salesID: 701
    };
}
