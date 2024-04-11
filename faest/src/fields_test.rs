use crate::fields::GF64;
#[cfg(test)]
use crate::fields::{GalloisField, GF8};
use rand::random;

//GF8 
#[test]
//Precondition = None
//Post contidtion = GF8 whose get_value is as expected
fn GF8_test_new_and_get_value(){
    let x : u8 = random();
    let polynome = GF8::new(x);
    assert_eq!(x, polynome.get_value());
}

#[test]
//should be equal to u8::MAX
fn GF8_test_get_max(){
    assert_eq!(GF8::get_max(), u8::MAX);
}

#[test]
//Should be equal to 8
fn GF8_test_get_bit(){
    assert_eq!(GF8::get_bit_usize(), 8usize);
}

#[test]
//precondtion : the GF8 polynome with a value x
//postconition : the value of GF8 polynome is y
fn GF8_test_set_value(){
    let mut polynome = GF8::new(67u8);
    assert_eq!(polynome.get_value(), 67u8);
    polynome.set_value(243u8);
    assert_eq!(polynome.get_value(), 243u8);
}

#[test]
//2 * 135 should be equal to 21
//0 * anything should be equal to 0
//anything * 0 should be equal to 0
//1 * anything should be equal to anything
//anything * 1 should beprintln!("{:?}", result_value); equal to anything
fn GF8_test_mul(){
    let pol_2 = GF8::new(2u8);
    let pol_135= GF8::new(135u8);
    let pol_21 = GF8::new(21u8);
    let anything = random();
    let pol_anything = GF8::new(anything);
    let pol_0 = GF8::new(0u8);
    let pol_1 = GF8::new(1u8);
    assert_eq!(GF8::mul(&pol_2, &pol_135), pol_21);
    assert_eq!(GF8::mul(&pol_0, &pol_anything), pol_0);
    assert_eq!(GF8::mul(&pol_anything, &pol_0), pol_0);
    assert_eq!(GF8::mul(&pol_1, &pol_anything), pol_anything);
    assert_eq!(GF8::mul(&pol_anything, &pol_1), pol_anything);
}

#[test]
//anything * inv(anything) should be equal to 1
fn GF8_test_inv(){
    let pol_1 = GF8::new(1u8);
    let anything = random();
    let pol_anything = GF8::new(anything);
    assert_eq!(GF8::mul(&pol_anything, &GF8::inv(GF8::new(anything))), pol_1);

}


//GF64

#[test]
//Precondition = None
//Post contidtion = GF64 whose get_value is as expected
fn GF64_test_new_and_get_value(){
    let x : u64 = random();
    let polynome = GF64::new(x);
    assert_eq!(x, polynome.get_value());
}

#[test]
//should be equal to u64::MAX
fn GF64_test_get_max(){
    assert_eq!(GF64::get_max(), u64::MAX);
}

#[test]
//Should be equal to 64
fn GF64_test_get_bit(){
    assert_eq!(GF64::get_bit_usize(), 64usize);
}

#[test]
//precondtion : the GF64 polynome with a value x
//postconition : the value of GF64 polynome is y
fn GF64_test_set_value(){
    let mut polynome = GF64::new(0xe367u64);
    assert_eq!(polynome.get_value(), 0xe367u64);
    polynome.set_value(0x243u64);
    assert_eq!(polynome.get_value(), 0x243u64);
}

#[test]
//-----------------------------------
//0 * anything should be equal to 0
//anything * 0 should be equal to 0
//1 * anything should be equal to anything
//anything * 1 should be equal to anything
fn GF64_test_mul(){
    let anything = random();
    let pol_anything = GF64::new(anything);
    let pol_0 = GF64::new(0u64);
    let pol_1 = GF64::new(1u64);
    assert_eq!(GF64::mul(&pol_1, &pol_1), pol_1);
    assert_eq!(GF64::mul(&pol_0, &pol_anything), pol_0);
    assert_eq!(GF64::mul(&pol_anything, &pol_0), pol_0);
    assert_eq!(GF64::mul(&pol_1, &pol_anything), pol_anything);
    assert_eq!(GF64::mul(&pol_anything, &pol_1), pol_anything);
}




//GF128



//GF192



//GF256 




