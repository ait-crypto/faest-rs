pub trait PARAMOWF {
    const NK : u8;
    const R : u8;
    const SKE : u8;
    const SENC : u16;
    const L : u16;
    const LKE : u16;
    const LENC : u16;
    const BETA : u8;
    const C : u16;
    const NST : Option<u8>;
}

pub struct PARAMOWF128;

impl PARAMOWF for PARAMOWF128 {
    
    const NK : u8 = 4;
    
    const R : u8 = 10;
    
    const SKE : u8 = 40;
    
    const SENC : u16 = 160;
    
    const L : u16 = 1600;
    
    const LKE : u16 = 448;
    
    const LENC : u16 = 1152;
    
    const BETA : u8 = 1;
    
    const C : u16 = 200;
    
    const NST : Option<u8> = None; 
}

pub struct PARAMOWF192;

impl PARAMOWF for PARAMOWF192 {
    const NK : u8 = 6;

    const R : u8 = 12;

    const SKE : u8 = 32;

    const SENC : u16 = 192;

    const L : u16 = 3264;

    const LKE : u16 = 448;

    const LENC : u16 = 1408;

    const BETA : u8 = 2;

    const C : u16 = 416;

    const NST : Option<u8> = None;
}

pub struct PARAMOWF256;

impl PARAMOWF for PARAMOWF256 {
    const NK : u8 = 8;

    const R : u8 = 14;

    const SKE : u8 = 52;

    const SENC : u16 = 224;

    const L : u16 = 4000;

    const LKE : u16 = 672;

    const LENC : u16 = 1664;

    const BETA : u8 = 2;

    const C : u16 = 500;

    const NST : Option<u8> = None;
}

pub struct PARAMOWF128EM;

impl PARAMOWF for PARAMOWF128EM{
    
    const NK : u8 = 4;

    const R : u8 = 10;

    const SKE : u8 = 40;

    const SENC : u16 = 160;

    const L : u16 = 1280;

    const LKE : u16 = 448;

    const LENC : u16 = 1152;

    const BETA : u8 = 1;

    const C : u16 = 160;

    const NST : Option<u8> = Some(4);
}

pub struct PARAMOWF192EM;

impl PARAMOWF for PARAMOWF192EM{
    
    const NK : u8 = 6;

    const R : u8 = 12;

    const SKE : u8 = 32;

    const SENC : u16 = 288;

    const L : u16 = 2304;

    const LKE : u16 = 448;

    const LENC : u16 = 1408;

    const BETA : u8 = 2;

    const C : u16 = 288;

    const NST : Option<u8> = Some(6);
}

pub struct PARAMOWF256EM;

impl PARAMOWF for PARAMOWF256EM{
    
    const NK : u8 = 8;

    const R : u8 = 14;

    const SKE : u8 = 52;

    const SENC : u16 = 448;

    const L : u16 = 3584;

    const LKE : u16 = 672;

    const LENC : u16 = 1664;

    const BETA : u8 = 2;

    const C : u16 = 448;

    const NST : Option<u8> = Some(8);
}

pub trait PARAM {
    const LAMBDA : usize;
    const L : u16;
    const TAU : u8;
    const K0 : u8;
    const K1 : u8;
    const TAU0 : u8;
    const TAU1 : u8;
    const B : u8;
    const BETA : u8;
}

pub struct PARAM128S;

impl PARAM for PARAM128S {
    const LAMBDA : usize = 128;

    const L : u16 = 1600;

    const TAU : u8 = 11;

    const K0 : u8 = 12;

    const K1 : u8 = 11;

    const TAU0 : u8 = 7;

    const TAU1 : u8 = 4;

    const B : u8 = 16;

    const BETA : u8 = 1;
} 

pub struct PARAM128F;

impl PARAM for PARAM128F {
    const LAMBDA : usize = 128;

    const L : u16 = 1600;

    const TAU : u8 = 16;

    const K0 : u8 = 8;

    const K1 : u8 = 8;

    const TAU0 : u8 = 8;

    const TAU1 : u8 = 8;

    const B : u8 = 16;

    const BETA : u8 = 1;
} 

pub struct PARAM192S;

impl PARAM for PARAM192S {
    const LAMBDA : usize = 192;

    const L : u16 = 3264;

    const TAU : u8 = 16;

    const K0 : u8 = 12;

    const K1 : u8 = 12;

    const TAU0 : u8 = 8;

    const TAU1 : u8 = 8;

    const B : u8 = 16;

    const BETA : u8 = 2;
} 

pub struct PARAM192F;

impl PARAM for PARAM192F {
    const LAMBDA : usize = 192;

    const L : u16 = 3264;

    const TAU : u8 = 24;

    const K0 : u8 = 8;

    const K1 : u8 = 8;

    const TAU0 : u8 = 12;

    const TAU1 : u8 = 12;

    const B : u8 = 16;

    const BETA : u8 = 2;
} 

pub struct PARAM256S;

impl PARAM for PARAM256S {
    const LAMBDA : usize = 256;

    const L : u16 = 4000;

    const TAU : u8 = 22;

    const K0 : u8 = 12;

    const K1 : u8 = 11;

    const TAU0 : u8 = 14;

    const TAU1 : u8 = 8;

    const B : u8 = 16;

    const BETA : u8 = 2;
} 

pub struct PARAM256F;

impl PARAM for PARAM256F {
    const LAMBDA : usize = 256;

    const L : u16 = 4000;

    const TAU : u8 = 32;

    const K0 : u8 = 8;

    const K1 : u8 = 8;

    const TAU0 : u8 = 16;

    const TAU1 : u8 = 16;

    const B : u8 = 16;

    const BETA : u8 = 2;
} 


pub struct PARAM128SEM;

impl PARAM for PARAM128SEM {
    const LAMBDA : usize = 128;

    const L : u16 = 1280;

    const TAU : u8 = 11;

    const K0 : u8 = 12;

    const K1 : u8 = 11;

    const TAU0 : u8 = 7;

    const TAU1 : u8 = 4;

    const B : u8 = 16;

    const BETA : u8 = 1;
} 

pub struct PARAM128FEM;

impl PARAM for PARAM128FEM {
    const LAMBDA : usize = 128;

    const L : u16 = 1280;

    const TAU : u8 = 16;

    const K0 : u8 = 8;

    const K1 : u8 = 8;

    const TAU0 : u8 = 8;

    const TAU1 : u8 = 8;

    const B : u8 = 16;

    const BETA : u8 = 1;
} 

pub struct PARAM192SEM;

impl PARAM for PARAM192SEM {
    const LAMBDA : usize = 192;

    const L : u16 = 2304;

    const TAU : u8 = 16;

    const K0 : u8 = 12;

    const K1 : u8 = 12;

    const TAU0 : u8 = 8;

    const TAU1 : u8 = 8;

    const B : u8 = 16;

    const BETA : u8 = 2;
} 

pub struct PARAM192FEM;

impl PARAM for PARAM192FEM {
    const LAMBDA : usize = 192;

    const L : u16 = 2304;

    const TAU : u8 = 24;

    const K0 : u8 = 8;

    const K1 : u8 = 8;

    const TAU0 : u8 = 12;

    const TAU1 : u8 = 12;

    const B : u8 = 16;

    const BETA : u8 = 2;
} 

pub struct PARAM256SEM;

impl PARAM for PARAM256SEM {
    const LAMBDA : usize = 256;

    const L : u16 = 3584;

    const TAU : u8 = 22;

    const K0 : u8 = 12;

    const K1 : u8 = 11;

    const TAU0 : u8 = 14;

    const TAU1 : u8 = 8;

    const B : u8 = 16;

    const BETA : u8 = 2;
} 

pub struct PARAM256FEM;

impl PARAM for PARAM256FEM {
    const LAMBDA : usize = 256;

    const L : u16 = 3584;

    const TAU : u8 = 32;

    const K0 : u8 = 8;

    const K1 : u8 = 8;

    const TAU0 : u8 = 16;

    const TAU1 : u8 = 16;

    const B : u8 = 16;

    const BETA : u8 = 2;
} 


