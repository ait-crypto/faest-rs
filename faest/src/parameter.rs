use std::ops::{Add, Sub};
use generic_array::{GenericArray, ArrayLength};
use typenum::{Diff, Double, Prod, Sum, U0, U1, U10, U1024, U11, U12, U128, U14, U16, U160, U176, U192, U2, U200, U2048, U22, U224, U24, U256, U266, U288, U3, U312, U32, U384, U4, U40, U408, U4096, U416, U432, U448, U48, U480, U5, U500, U511, U512, U52, U544, U56, U576, U6, U64, U640, U672, U7, U704, U8, U8192, U832, U96};

use crate::fields::{BigGaloisField, GF128, GF192, GF256};
    

pub trait PARAMOWF<T> where T : BigGaloisField{
    type LAMBDA : ArrayLength<u8>;
    type LAMBDABYTES : ArrayLength<u8>;
    type L : ArrayLength<T>;
    type LBYTES : ArrayLength<u8>;
    type NK : ArrayLength<u8>;
    type R : ArrayLength<u8>;
    type SKE : ArrayLength<u8>;
    type SENC : ArrayLength<u8>;
    type LKE : ArrayLength<u8>;
    type LENC : ArrayLength<u8>;
    type BETA : ArrayLength<u8>;
    type C : ArrayLength<u8>;
    type NST : ArrayLength<u8>;
    type LAMBDALBYTES : ArrayLength<u8>;
    type PK : ArrayLength<u8>;
    type SK : ArrayLength<u8>;
    type CHALL : ArrayLength<u8>;
    type CHALL1 : ArrayLength<u8>;
    type CHALL2 : ArrayLength<u8>;
    type LHATBYTES : ArrayLength<u8>;
    type LAMBDAPLUSTWO : ArrayLength<u8>;
    type LAMBDADOUBLE : ArrayLength<u8>;
    type LAMBDATRIPLE : ArrayLength<u8>;
    type LAMBDAPLUS16 : ArrayLength<u8>;
    type LAMBDAPLUS4 : ArrayLength<u8>;
    type LBYTESPLUS4 : ArrayLength<u8>;
    type LPRIMEBYTE : ArrayLength<u8>; 
}

pub struct PARAMOWF128;

impl PARAMOWF<GF128> for PARAMOWF128 {

    type LAMBDA = U128;
    
    type LAMBDABYTES  = U16;
    
    type L = <U1024 as Add<U576>>::Output ;
    
    type LBYTES = U200;
    
    type LAMBDALBYTES = <Self::LAMBDABYTES as Add<Self::LBYTES>>::Output; 
    
    type NK = U4;
    
    type R = U10;
    
    type SKE = U40;
    
    type SENC = U160;
    
    type LKE = U448;
    
    type LENC = <U1024 as Add<U128>>::Output ;
    
    type BETA = U1;
    
    type C = U200;
    
    type NST = U0;

    type PK = U32;

    type SK = U32;

    type CHALL = Sum<U8, Prod<U3, Self::LAMBDABYTES>>;

    type CHALL1 = Sum<U8, Prod<U5, Self::LAMBDABYTES>>;
    
    type CHALL2 = Sum<U8, Prod<U3, Self::LAMBDABYTES>>;

    type LHATBYTES = Sum<Self::LBYTES, Sum<Prod<U2, Self::LAMBDABYTES>, U2>>;

    type LAMBDAPLUSTWO = Sum<Self::LAMBDABYTES, U2>;

    type LAMBDADOUBLE = Double<Self::LAMBDABYTES>;

    type LAMBDAPLUS16 = Sum<Self::LAMBDABYTES, U16>;
    
    type LAMBDAPLUS4 = Sum<Self::LAMBDABYTES, U4>;
    
    type LBYTESPLUS4 = Sum<Self::LBYTES, U4>;
    
    type LPRIMEBYTE = U256;
    
    type LAMBDATRIPLE = Prod<U3, Self::LAMBDABYTES>;


}

pub struct PARAMOWF192;

impl PARAMOWF<GF192> for PARAMOWF192 {

    type LAMBDA = U192;

    type LAMBDABYTES = U24;

    type L = <U4096 as Sub<U832>>::Output ;

    type LBYTES = U408;
    
    type LAMBDALBYTES = <Self::LAMBDABYTES as Add<Self::LBYTES>>::Output; 
    
    type NK = U6;
    
    type R = U12;
    
    type SKE = U32;
    
    type SENC = U192;

    type LKE = U448;
    
    type LENC = <U1024 as Add<U384>>::Output ;
    
    type BETA = U2;
    
    type C = U416;
    
    type NST = U0;
    
    type PK = U64;

    type SK = U64;

    type CHALL = Sum<U8, Prod<U3, Self::LAMBDABYTES>>;

    type CHALL1 = Sum<U8, Prod<U5, Self::LAMBDABYTES>>;
    
    type CHALL2 = Sum<U8, Prod<U3, Self::LAMBDABYTES>>;

    type LHATBYTES = Sum<Self::LBYTES, Sum<Prod<U2, Self::LAMBDABYTES>, U2>>;

    type LAMBDAPLUSTWO = Sum<Self::LAMBDABYTES, U2>;

    type LAMBDADOUBLE = Double<Self::LAMBDABYTES>;

    type LAMBDAPLUS16 = Sum<Self::LAMBDABYTES, U16>;  
    
    type LAMBDAPLUS4 = Sum<Self::LAMBDABYTES, U4>;
    
    type LBYTESPLUS4 = Sum<Self::LBYTES, U4>;

    type LPRIMEBYTE = U384;

    type LAMBDATRIPLE = Prod<U3, Self::LAMBDABYTES>;

}


pub struct PARAMOWF256;

impl PARAMOWF<GF256> for PARAMOWF256 {

    type LAMBDA = U256;

    type LAMBDABYTES = U32;
    
    type L = <U4096 as Sub<U96>>::Output ;

    type LBYTES = U500;
    
    type LAMBDALBYTES = <Self::LAMBDABYTES as Add<Self::LBYTES>>::Output; 
    
    type NK = U8;
    
    type R = U14;
    
    type SKE = U52;
    
    type SENC = U224;
    
    type LKE = U672;
    
    type LENC = <U1024 as Add<U640>>::Output ;
    
    type BETA = U2;
    
    type C = U500;
    
    type NST = U0;

    type PK = U64;

    type SK = U64;

    type CHALL = Sum<U8, Prod<U3, Self::LAMBDABYTES>>;

    type CHALL1 = Sum<U8, Prod<U5, Self::LAMBDABYTES>>;
    
    type CHALL2 = Sum<U8, Prod<U3, Self::LAMBDABYTES>>;

    type LHATBYTES = Sum<Self::LBYTES, Sum<Prod<U2, Self::LAMBDABYTES>, U2>>;

    type LAMBDAPLUSTWO = Sum<Self::LAMBDABYTES, U2>;

    type LAMBDADOUBLE = Double<Self::LAMBDABYTES>;

    type LAMBDAPLUS16 = Sum<Self::LAMBDABYTES, U16>;

    type LAMBDAPLUS4 = Sum<Self::LAMBDABYTES, U4>;
    
    type LBYTESPLUS4 = Sum<Self::LBYTES, U4>;

    type LPRIMEBYTE = U512;

    type LAMBDATRIPLE = Prod<U3, Self::LAMBDABYTES>;

}

pub struct PARAMOWF128EM;

impl PARAMOWF<GF128> for PARAMOWF128EM {

    type LAMBDA = U128;

    type LAMBDABYTES = U16;

    type L = <U1024 as Add<U266>>::Output;

    type LBYTES = U160;
    
    type LAMBDALBYTES = <Self::LAMBDABYTES as Add<Self::LBYTES>>::Output; 
    
    type NK = U4;
    
    type R = U10;
    
    type SKE = U40;
    
    type SENC = U160;
    
    type LKE = U448;
    
    type LENC = <U1024 as Add<U128>>::Output ;
    
    type BETA = U1;
    
    type C = U160;
    
    type NST = U4;

    type PK = U32;

    type SK = U32;
    
    type CHALL = Sum<U8, Prod<U3, Self::LAMBDABYTES>>;

    type CHALL1 = Sum<U8, Prod<U5, Self::LAMBDABYTES>>;
    
    type CHALL2 = Sum<U8, Prod<U3, Self::LAMBDABYTES>>;

    type LHATBYTES = Sum<Self::LBYTES, Sum<Prod<U2, Self::LAMBDABYTES>, U2>>;

    type LAMBDAPLUSTWO = Sum<Self::LAMBDABYTES, U2>;

    type LAMBDADOUBLE = Double<Self::LAMBDABYTES>;

    type LAMBDAPLUS16 = Sum<Self::LAMBDABYTES, U16>;

    type LAMBDAPLUS4 = Sum<Self::LAMBDABYTES, U4>;
    
    type LBYTESPLUS4 = Sum<Self::LBYTES, U4>;

    type LPRIMEBYTE = U256;

    type LAMBDATRIPLE = Prod<U3, Self::LAMBDABYTES>;

    
}

pub struct PARAMOWF192EM;

impl PARAMOWF<GF192> for PARAMOWF192EM {

    type LAMBDA = U192;
    
    type LAMBDABYTES = U24;
    
    type L = <U2048 as Add<U256>>::Output;
   
    type LBYTES = U288;
       
    type LAMBDALBYTES = <Self::LAMBDABYTES as Add<Self::LBYTES>>::Output; 
    
    type NK = U6;
    
    type R = U12;
    
    type SKE = U32;
    
    type SENC = U288;
    
    type LKE = U448;
    
    type LENC = <U1024 as Add<U384>>::Output ;
    
    type BETA = U2;
    
    type C = U288;
    
    type NST = U6;

    type PK = U48;

    type SK = U48;

    type CHALL = Sum<U8, Prod<U3, Self::LAMBDABYTES>>;

    type CHALL1 = Sum<U8, Prod<U5, Self::LAMBDABYTES>>;
    
    type CHALL2 = Sum<U8, Prod<U3, Self::LAMBDABYTES>>;

    type LHATBYTES = Sum<Self::LBYTES, Sum<Prod<U2, Self::LAMBDABYTES>, U2>>;
    
    type LAMBDAPLUSTWO = Sum<Self::LAMBDABYTES, U2>;

    type LAMBDADOUBLE = Double<Self::LAMBDABYTES>;

    type LAMBDAPLUS16 = Sum<Self::LAMBDABYTES, U16>;

    type LAMBDAPLUS4 = Sum<Self::LAMBDABYTES, U4>;
    
    type LBYTESPLUS4 = Sum<Self::LBYTES, U4>;

    type LPRIMEBYTE = U384;

    type LAMBDATRIPLE = Prod<U3, Self::LAMBDABYTES>;

}

pub struct PARAMOWF256EM;

impl PARAMOWF<GF256> for PARAMOWF256EM {

    type LAMBDA = U256;

    type LAMBDABYTES = U32;
 
    type L = <U4096 as Add<U512>>::Output;
    
    type LBYTES = U448;
     
    type LAMBDALBYTES = <Self::LAMBDABYTES as Add<Self::LBYTES>>::Output; 
    
    type NK = U8;
    
    type R = U14;
    
    type SKE = U52;
    
    type SENC = U448;
    
    type LKE = U672;
    
    type LENC = <U1024 as Add<U640>>::Output ;
    
    type BETA = U2;
    
    type C = U448;
    
    type NST = U8;

    type PK = U64;

    type SK = U64;

    type CHALL = Sum<U8, Prod<U3, Self::LAMBDABYTES>>;

    type CHALL1 = Sum<U8, Prod<U5, Self::LAMBDABYTES>>;
    
    type CHALL2 = Sum<U8, Prod<U3, Self::LAMBDABYTES>>;

    type LHATBYTES = Sum<Self::LBYTES, Sum<Prod<U2, Self::LAMBDABYTES>, U2>>;

    type LAMBDAPLUSTWO = Sum<Self::LAMBDABYTES, U2>;

    type LAMBDADOUBLE = Double<Self::LAMBDABYTES>;

    type LAMBDAPLUS16 = Sum<Self::LAMBDABYTES, U16>;
    
    type LAMBDAPLUS4 = Sum<Self::LAMBDABYTES, U4>;
    
    type LBYTESPLUS4 = Sum<Self::LBYTES, U4>;

    type LPRIMEBYTE = U512;

    type LAMBDATRIPLE = Prod<U3, Self::LAMBDABYTES>;

    
}



pub trait PARAM {
    type L : ArrayLength<u8>;
    type LBYTES : ArrayLength<u8>;
    type TAU : ArrayLength<u8>;
    type TAUMINUS :ArrayLength<u8>;
    type K0 : ArrayLength<u8>;
    type N0 : ArrayLength<u8>;
    type POWK0 : ArrayLength<u8>;
    type K1 : ArrayLength<u8>;
    type N1 : ArrayLength<u8>;
    type POWK1 : ArrayLength<u8>;
    type TAU0 : ArrayLength<u8>;
    type TAU1 : ArrayLength<u8>;
    type B : ArrayLength<u8>;
    type BETA : ArrayLength<u8>;
    type LAMBDA : ArrayLength<u8>;
    type PRODLAMBDATAU : ArrayLength<u8>;
}

pub struct PARAM128S;

impl PARAM for PARAM128S {

    type L = <U1024 as Add<U576>>::Output ;
    
    type LBYTES = U200;

    type TAU = U11;

    type TAUMINUS = Diff<Self::TAU, U1>;

    type K0 = U12;

    type K1 = U11;

    type TAU0 = U7;

    type TAU1 = U4;

    type B = U16;

    type BETA = U1;
    
    type LAMBDA = U128;
    
    type N0 = U4096;
    
    type POWK0 = Diff<U8192, U1>;
    
    type N1 = U2048;
    
    type POWK1 = Diff<U4096, U1>;
    
    type PRODLAMBDATAU = U176;
    
    
} 

pub struct PARAM128F;

impl PARAM for PARAM128F {

    type L = <U1024 as Add<U576>>::Output ;

    type LBYTES = U200;

    type TAU = U16;

    type TAUMINUS = Diff<Self::TAU, U1>;

    type K0 = U8;

    type K1 = U8;

    type TAU0 = U8;

    type TAU1 = U8;

    type B = U16;

    type BETA = U1;
    
    type LAMBDA = U128;
    
    type N0 = U256;
    
    type POWK0 = U511;
    
    type N1 = U256;
    
    type POWK1 = U511;
    
    type PRODLAMBDATAU = U256;

} 

pub struct PARAM192S;

impl PARAM for PARAM192S {
    

    type L = <U4096 as Sub<U832>>::Output ;

    type LBYTES = U408;

    type TAU = U16;

    type TAUMINUS = Diff<Self::TAU, U1>;

    type K0 = U12;

    type K1 = U12;

    type TAU0 = U8;

    type TAU1 = U8;

    type B = U16;

    type BETA = U2;
    
    type LAMBDA = U192;
    
    type N0 = U4096;
    
    type POWK0 = Diff<U8192, U1>;
    
    type N1 = U4096;
    
    type POWK1 = Diff<U8192, U1>;
    
    type PRODLAMBDATAU = U384;
    
    

    
} 

pub struct PARAM192F;

impl PARAM for PARAM192F {

    type L = <U4096 as Sub<U832>>::Output ;

    type LBYTES = U408;

    type TAU = U24;

    type TAUMINUS = Diff<Self::TAU, U1>;

    type K0 = U8;

    type K1 = U8;

    type TAU0 = U12;

    type TAU1 = U12;

    type B = U16;

    type BETA = U2;
    
    type LAMBDA = U192;
    
    type N0 = U256;
    
    type POWK0 = U511;
    
    type N1 = U256;
    
    type POWK1 = U511;
    
    type PRODLAMBDATAU = U576;
 
} 

pub struct PARAM256S;

impl PARAM for PARAM256S {
    

    type L = <U4096 as Sub<U96>>::Output ;

    type LBYTES = U500;

    type TAU = U22;

    type TAUMINUS = Diff<Self::TAU, U1>;

    type K0 = U12;

    type K1 = U11;

    type TAU0 = U14;

    type TAU1 = U8;

    type B = U16;

    type BETA = U2;
    
    type LAMBDA = U256;
    
    type N0 = U4096;
    
    type POWK0 = Diff<U8192, U1>;
    
    type N1 = U2048;
    
    type POWK1 = Diff<U4096, U1>;
    
    type PRODLAMBDATAU = U704;
    
} 

pub struct PARAM256F;

impl PARAM for PARAM256F {

    type L = <U4096 as Sub<U96>>::Output;

    type LBYTES = U500;

    type TAU = U32;

    type TAUMINUS = Diff<Self::TAU, U1>;

    type K0 = U8;

    type K1 = U8;

    type TAU0 = U16;

    type TAU1 = U16;

    type B = U16;

    type BETA = U2;
    
    type LAMBDA = U256;
    
    type N0 = U256;
    
    type POWK0 = U511;
    
    type N1 = U256;
    
    type POWK1 = U511;
    
    type PRODLAMBDATAU = U1024;
 
} 


pub struct PARAM128SEM;

impl PARAM for PARAM128SEM {

    type L = <U1024 as Add<U266>>::Output;

    type LBYTES = U160;

    type TAU = U11;

    type TAUMINUS = Diff<Self::TAU, U1>;

    type K0 = U12;

    type K1 = U11;

    type TAU0 = U7;

    type TAU1 = U4;

    type B = U16;

    type BETA = U1;
    
    type LAMBDA = U128;
    
    type N0 = U4096;
    
    type POWK0 = Diff<U8192, U1>;
    
    type N1 = U2048;
    
    type POWK1 = Diff<U4096, U1>;
    
    type PRODLAMBDATAU = U176;

} 

pub struct PARAM128FEM;

impl PARAM for PARAM128FEM {
    

    type L = <U1024 as Add<U266>>::Output;

    type LBYTES = U160;

    type TAU = U16;

    type TAUMINUS = Diff<Self::TAU, U1>;

    type K0 = U8;

    type K1 = U8;

    type TAU0 = U8;

    type TAU1 = U8;

    type B = U16;
    
    type BETA = U1;
    
    type LAMBDA = U128;
    
    type N0 = U256;
    
    type POWK0 = U511;
    
    type N1 = U256;
    
    type POWK1 = U511;
    
    type PRODLAMBDATAU = U256;
    
    
} 

pub struct PARAM192SEM;

impl PARAM for PARAM192SEM {
   

    type L = <U2048 as Add<U256>>::Output;

    type LBYTES = U288;

    type TAU = U16;

    type TAUMINUS = Diff<Self::TAU, U1>;

    type K0 = U12;

    type K1 = U12;

    type TAU0 = U8;

    type TAU1 = U8;

    type B = U16;

    type BETA = U2;
    
    type LAMBDA = U192;
    
    type N0 = U4096;
    
    type POWK0 = Diff<U8192, U1>;
    
    type N1 = U4096;
    
    type POWK1 = Diff<U8192, U1>;
    
    type PRODLAMBDATAU = U384;
    
    

    
} 

pub struct PARAM192FEM;

impl PARAM for PARAM192FEM {
    type L = <U2048 as Add<U256>>::Output;
    
    type LBYTES = U288;

    type TAU = U24;

    type TAUMINUS = Diff<Self::TAU, U1>;

    type K0 = U8;

    type K1 = U8;

    type TAU0 = U12;

    type TAU1 = U12;

    type B = U16;

    type BETA = U2;
    
    type LAMBDA = U192;
    
    type N0 = U256;
    
    type POWK0 = U511;
    
    type N1 = U256;
    
    type POWK1 = U511;
    
    type PRODLAMBDATAU = U576;
} 

pub struct PARAM256SEM;

impl PARAM for PARAM256SEM {
    
    type L = <U4096 as Add<U512>>::Output;
    
    type LBYTES = U448;

    type TAU = U22;

    type TAUMINUS = Diff<Self::TAU, U1>;

    type K0 = U12;

    type K1 = U11;

    type TAU0 = U14;

    type TAU1 = U8;

    type B = U16;

    type BETA = U2;
    
    type LAMBDA = U256;
    
    type N0 = U4096;
    
    type POWK0 = Diff<U8192, U1>;
    
    type N1 = U2048;
    
    type POWK1 = Diff<U4096, U1>;
    
    type PRODLAMBDATAU = U704;
    
    

   
} 

pub struct PARAM256FEM;

impl PARAM for PARAM256FEM {

    type L = <U4096 as Add<U512>>::Output;
    
    type LBYTES = U448;

    type TAU = U32;

    type TAUMINUS = Diff<Self::TAU, U1>;

    type K0 = U8;

    type K1 = U8;

    type TAU0 = U16;

    type TAU1 = U16;

    type B = U16;

    type BETA = U2;
    
    type LAMBDA = U256;
    
    type N0 = U256;
    
    type POWK0 = U511;
    
    type N1 = U256;
    
    type POWK1 = U511;
    
    type PRODLAMBDATAU = U1024;



} 


