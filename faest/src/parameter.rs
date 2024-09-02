use std::ops::{Add, Sub};

use generic_array::{ArrayLength};
use typenum::{Diff, Double, Prod, Quot, Sum, U0, U1, U10, U1024, U11, U112, U12, U128, U14, U142, U152, U16, U160, U16384, U176, U192, U194, U2, U200, U2048, U22, U224, U234, U24, U256, U266, U288, U3, U32, U338, U352, U384, U4, U40, U408, U4096, U416, U448, U458, U470, U476, U48, U5, U500, U511, U512, U514, U52, U544, U566, U576, U584, U596, U6, U600, U64, U640, U672, U7, U704, U752, U8, U8192, U832, U96};


    

pub trait PARAMOWF{
    type XK: ArrayLength;
    type LAMBDA : ArrayLength;
    type LAMBDABYTES : ArrayLength;
    type L : ArrayLength;
    type LBYTES : ArrayLength;
    type NK : ArrayLength;
    type R : ArrayLength;
    type SKE : ArrayLength;
    type SENC : ArrayLength;
    type QUOTSENC4 : ArrayLength;
    type LKE : ArrayLength;
    type LENC : ArrayLength;
    type QUOTLENC8 : ArrayLength;
    type BETA : ArrayLength;
    type C : ArrayLength;
    type NST : ArrayLength;
    type LAMBDALBYTES : ArrayLength;
    type LAMBDAL : ArrayLength;
    type PK : ArrayLength;
    type QUOTPK2 : ArrayLength;
    type SK : ArrayLength;
    type CHALL : ArrayLength;
    type CHALL1 : ArrayLength;
    type LHATBYTES : ArrayLength;
    type LAMBDAPLUS2 : ArrayLength;
    type LAMBDADOUBLE : ArrayLength;
    type LAMBDATRIPLE : ArrayLength;
    type LAMBDAPLUS16 : ArrayLength;
    type LAMBDAPLUS4 : ArrayLength;
    type LBYTESPLUS4 : ArrayLength;
    type LPRIMEBYTE : ArrayLength; 
    type KBLENGTH : ArrayLength;
    type PRODRUN128 : ArrayLength;
    type PRODSKE8 : ArrayLength;
    type SENC2 : ArrayLength;
    type LAMBDALBYTESLAMBDA : ArrayLength;
    type LAMBDAR1 : ArrayLength;
    type LAMBDAR1BYTE : ArrayLength;
}

pub struct PARAMOWF128;

impl PARAMOWF for PARAMOWF128 {

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

    type LHATBYTES = Sum<Self::LBYTES, Sum<Prod<U2, Self::LAMBDABYTES>, U2>>;

    type LAMBDAPLUS2 = Sum<Self::LAMBDABYTES, U2>;

    type LAMBDADOUBLE = Double<Self::LAMBDABYTES>;

    type LAMBDAPLUS16 = Sum<Self::LAMBDABYTES, U16>;
    
    type LAMBDAPLUS4 = Sum<Self::LAMBDABYTES, U4>;
    
    type LBYTESPLUS4 = Sum<Self::LBYTES, U4>;
    
    type LPRIMEBYTE = U256;
    
    type LAMBDATRIPLE = Prod<U3, Self::LAMBDABYTES>;
    
    type KBLENGTH = Prod<Sum<Self::R, U1>, U8>;
    
    type PRODRUN128 = Prod<Sum<Self::R, U1>, U128>;
    
    type PRODSKE8 = Prod<Self::SKE, U8>;
    
    type SENC2 = Prod<Self::SENC, U2>;
    
    type LAMBDALBYTESLAMBDA = Prod<Self::LAMBDA, Self::LAMBDALBYTES>;
    
    type QUOTLENC8 = Quot<Self::LENC, U8>;
    
    type LAMBDAL = Sum<Self::LAMBDA, Self::L>;
    
    type QUOTSENC4 = Quot<Self::SENC, U4> ;
    
    type QUOTPK2 = Quot<Self::PK, U2> ;
    
    type LAMBDAR1 = Prod<Self::LAMBDA, Sum<Self::R, U1>>;
    
    type LAMBDAR1BYTE = Quot<Self::LAMBDAR1, U8> ;
    
    type XK = Sum<U1024, U160>;


}

pub struct PARAMOWF192;

impl PARAMOWF for PARAMOWF192 {

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

    type LHATBYTES = Sum<Self::LBYTES, Sum<Prod<U2, Self::LAMBDABYTES>, U2>>;

    type LAMBDAPLUS2 = Sum<Self::LAMBDABYTES, U2>;

    type LAMBDADOUBLE = Double<Self::LAMBDABYTES>;

    type LAMBDAPLUS16 = Sum<Self::LAMBDABYTES, U16>;  
    
    type LAMBDAPLUS4 = Sum<Self::LAMBDABYTES, U4>;

    type LBYTESPLUS4 = Sum<Self::LBYTES, U4>;

    type LPRIMEBYTE = U384;

    type LAMBDATRIPLE = Prod<U3, Self::LAMBDABYTES>;


    type KBLENGTH = Prod<Sum<Self::R, U1>, U8>;

    type PRODRUN128 = Prod<Sum<Self::R, U1>, U128>;

    type PRODSKE8 = Prod<Self::SKE, U8>;

    type SENC2 = Prod<Self::SENC, U2>;
    
    type LAMBDALBYTESLAMBDA = Prod<Self::LAMBDA, Self::LAMBDALBYTES>;

    type QUOTLENC8 = Quot<Self::LENC, U8>;

    type LAMBDAL = Sum<Self::LAMBDA, Self::L>;

    type QUOTSENC4 = Quot<Self::SENC, U4> ;

    type QUOTPK2 = Quot<Self::PK, U2> ;

    type LAMBDAR1 = Prod<Self::LAMBDA, Sum<Self::R, U1>>;

    type LAMBDAR1BYTE = Quot<Self::LAMBDAR1, U8> ;

    type XK = Sum<U1024, U352>;

}


pub struct PARAMOWF256;

impl PARAMOWF for PARAMOWF256 {

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

    type LHATBYTES = Sum<Self::LBYTES, Sum<Prod<U2, Self::LAMBDABYTES>, U2>>;

    type LAMBDAPLUS2 = Sum<Self::LAMBDABYTES, U2>;

    type LAMBDADOUBLE = Double<Self::LAMBDABYTES>;

    type LAMBDAPLUS16 = Sum<Self::LAMBDABYTES, U16>;

    type LAMBDAPLUS4 = Sum<Self::LAMBDABYTES, U4>;
    
    type LBYTESPLUS4 = Sum<Self::LBYTES, U4>;

    type LPRIMEBYTE = U512;

    type LAMBDATRIPLE = Prod<U3, Self::LAMBDABYTES>;


    type KBLENGTH = Prod<Sum<Self::R, U1>, U8>;

    type PRODRUN128 = Prod<Sum<Self::R, U1>, U128>;

    type PRODSKE8 = Prod<Self::SKE, U8>;

    type SENC2 = Prod<Self::SENC, U2>;

    type LAMBDALBYTESLAMBDA = Prod<Self::LAMBDA, Self::LAMBDALBYTES>;

    type QUOTLENC8 = Quot<Self::LENC, U8>;

    type LAMBDAL = Sum<Self::LAMBDA, Self::L>;

    type QUOTSENC4 = Quot<Self::SENC, U4> ;

    type QUOTPK2 = Quot<Self::PK, U2> ;

    type LAMBDAR1 = Prod<Self::LAMBDA, Sum<Self::R, U1>>;

    type LAMBDAR1BYTE = Quot<Self::LAMBDAR1, U8> ;

    type XK = Sum<U1024, U544>;

}

pub struct PARAMOWF128EM;

impl PARAMOWF for PARAMOWF128EM {

    type LAMBDA = U128;

    type LAMBDABYTES = U16;

    type L = <U1024 as Add<U256>>::Output;

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

    type LHATBYTES = Sum<Self::LBYTES, Sum<Prod<U2, Self::LAMBDABYTES>, U2>>;

    type LAMBDAPLUS2 = Sum<Self::LAMBDABYTES, U2>;

    type LAMBDADOUBLE = Double<Self::LAMBDABYTES>;

    type LAMBDAPLUS16 = Sum<Self::LAMBDABYTES, U16>;

    type LAMBDAPLUS4 = Sum<Self::LAMBDABYTES, U4>;
    
    type LBYTESPLUS4 = Sum<Self::LBYTES, U4>;

    type LPRIMEBYTE = U256;

    type LAMBDATRIPLE = Prod<U3, Self::LAMBDABYTES>;

    
    type KBLENGTH = Prod<Sum<Self::R, U1>, U8>;

    type PRODRUN128 = Prod<Sum<Self::R, U1>, U128>;

    type PRODSKE8 = Prod<Self::SKE, U8>;

    type SENC2 = Prod<Self::SENC, U2>;

    type LAMBDALBYTESLAMBDA = Prod<Self::LAMBDA, Self::LAMBDALBYTES>;

    type QUOTLENC8 = Quot<Self::LENC, U8>;

    type LAMBDAL = Sum<Self::LAMBDA, Self::L>;

    type QUOTSENC4 = Quot<Self::SENC, U4> ;

    type QUOTPK2 = Quot<Self::PK, U2> ;

    type LAMBDAR1 = Prod<Self::LAMBDA, Sum<Self::R, U1>>;

    type LAMBDAR1BYTE = Quot<Self::LAMBDAR1, U8> ;
    type XK = Sum<U1024, U160>;

}

pub struct PARAMOWF192EM;

impl PARAMOWF for PARAMOWF192EM {

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

    type LHATBYTES = Sum<Self::LBYTES, Sum<Prod<U2, Self::LAMBDABYTES>, U2>>;
    
    type LAMBDAPLUS2 = Sum<Self::LAMBDABYTES, U2>;

    type LAMBDADOUBLE = Double<Self::LAMBDABYTES>;

    type LAMBDAPLUS16 = Sum<Self::LAMBDABYTES, U16>;

    type LAMBDAPLUS4 = Sum<Self::LAMBDABYTES, U4>;
    
    type LBYTESPLUS4 = Sum<Self::LBYTES, U4>;

    type LPRIMEBYTE = U384;

    type LAMBDATRIPLE = Prod<U3, Self::LAMBDABYTES>;


    type KBLENGTH = Prod<Sum<Self::R, U1>, U8>;

    type PRODRUN128 = Prod<Sum<Self::R, U1>, U128>;

    type PRODSKE8 = Prod<Self::SKE, U8>;

    type SENC2 = Prod<Self::SENC, U2>;

    type LAMBDALBYTESLAMBDA = Prod<Self::LAMBDA, Self::LAMBDALBYTES>;

    type QUOTLENC8 = Quot<Self::LENC, U8>;

    type LAMBDAL = Sum<Self::LAMBDA, Self::L>;

    type QUOTSENC4 = Quot<Self::SENC, U4> ;

    type QUOTPK2 = Quot<Self::PK, U2> ;

    type LAMBDAR1 = Prod<Self::LAMBDA, Sum<Self::R, U1>>;

    type LAMBDAR1BYTE = Quot<Self::LAMBDAR1, U8> ;

    type XK = Sum<U1024, U160>;

}

pub struct PARAMOWF256EM;

impl PARAMOWF for PARAMOWF256EM {

    type LAMBDA = U256;

    type LAMBDABYTES = U32;
 
    type L = <U4096 as Sub<U512>>::Output;
    
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

    type LHATBYTES = Sum<Self::LBYTES, Sum<Prod<U2, Self::LAMBDABYTES>, U2>>;

    type LAMBDAPLUS2 = Sum<Self::LAMBDABYTES, U2>;

    type LAMBDADOUBLE = Double<Self::LAMBDABYTES>;

    type LAMBDAPLUS16 = Sum<Self::LAMBDABYTES, U16>;
    
    type LAMBDAPLUS4 = Sum<Self::LAMBDABYTES, U4>;
    
    type LBYTESPLUS4 = Sum<Self::LBYTES, U4>;

    type LPRIMEBYTE = U512;

    type LAMBDATRIPLE = Prod<U3, Self::LAMBDABYTES>;
    

    type KBLENGTH = Prod<Sum<Self::R, U1>, U8>;

    type PRODRUN128 = Prod<Sum<Self::R, U1>, U128>;

    type PRODSKE8 = Prod<Self::SKE, U8>;

    type SENC2 = Prod<Self::SENC, U2>;

    type LAMBDALBYTESLAMBDA = Prod<Self::LAMBDA, Self::LAMBDALBYTES>;

    type QUOTLENC8 = Quot<Self::LENC, U8>;

    type LAMBDAL = Sum<Self::LAMBDA, Self::L>;

    type QUOTSENC4 = Quot<Self::SENC, U4> ;

    type QUOTPK2 = Quot<Self::PK, U2> ;

    type LAMBDAR1 = Prod<Self::LAMBDA, Sum<Self::R, U1>>;

    type LAMBDAR1BYTE = Quot<Self::LAMBDAR1, U8> ;

    type XK = Sum<U1024, U160>;

}



pub trait PARAM {
    //type Field: BigGaloisField;
    type L : ArrayLength;
    type LBYTES : ArrayLength;
    type TAU : ArrayLength;
    type TAUMINUS :ArrayLength;
    type K0 : ArrayLength;
    type N0 : ArrayLength;
    type POWK0 : ArrayLength;
    type K1 : ArrayLength;
    type N1 : ArrayLength;
    type POWK1 : ArrayLength;
    type TAU0 : ArrayLength;
    type TAU1 : ArrayLength;
    type B : ArrayLength;
    type BETA : ArrayLength;
    type LAMBDA : ArrayLength;
    type PRODLAMBDATAU : ArrayLength;
    type LH :ArrayLength;
    type SIG :ArrayLength;
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

    type LH = U234;
    
    type SIG = Sum<U142, Sum<U256, Sum<U512, U4096>>>;
    
    
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

    type LH = U234;
    
    type SIG = Sum<U192, Sum<U2048, U4096>>;

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
    
    type LH = U458;
    
    type SIG = Sum<U200, Sum<U256, Sum<U8192, U4096>>>;

    
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

    type LH = U458;
    
    type SIG = Sum<U152, Sum<U256, U16384>>;
 
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

    type LH = U566;
    
    type SIG = Sum<U596, Sum<U1024, Sum<U4096, U16384>>>;
    
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

    type LH = U566;
    
    type SIG = Sum<U752, Sum<U1024, Sum<U2048, Sum<U8192, U16384>>>>;
 
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

    type LH = U194;
    
    type SIG = Sum<U470, U4096>;

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

    type LH = U194;
    
    type SIG = Sum<U576, Sum<U1024, U4096>>;
    
    
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
    
    type LH = U338;
    
    type SIG = Sum<U584, Sum<U2048, U8192>>;

    
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

    type LH = U338;
    
    type SIG = Sum<U600, Sum<U1024, Sum<U4096, U8192>>>;

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
    
    type LH = U514;
    
    type SIG = Sum<U476, Sum<U4096, U16384>>;

   
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

    type LH = U514;
    
    type SIG = Sum<U112, Sum<U2048, Sum<U8192, U16384>>>;

} 




