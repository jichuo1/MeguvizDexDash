use mdd_query::budget::QueueDeliveryReceipt;

fn main() {
    let _forged = QueueDeliveryReceipt { tracker: panic!("never"), consumed: true };
}
