use crate::fields::{self, GalloisField, GF8};






#[test]
fn test_rand_t() {
    let acht:GF8 = GF8::rand_polynome();
    println!("{:?}", acht.value)
}


