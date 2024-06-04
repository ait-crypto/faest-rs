pub const PARAMOWF128 : ParamOWF = ParamOWF { nk : 4, r : 10, ske : 40, senc : 160, l : 1600, lke : 448, lenc : 1152, beta : 1, c : 200, nst : None};
pub const PARAMOWF192 : ParamOWF = ParamOWF { nk : 6, r : 12, ske : 32, senc : 192, l : 3264, lke : 448, lenc : 1408, beta : 2, c : 416, nst : None};
pub const PARAMOWF256 : ParamOWF = ParamOWF { nk : 8, r : 14, ske : 52, senc : 224, l : 4000, lke : 672, lenc : 1664, beta : 2, c : 500, nst : None};

pub struct ParamOWF {
    nk : u8,
    r : u8,
    ske : u8,
    senc : u8,
    l : u16,
    lke : u16,
    lenc : u16,
    beta : u8,
    c : u16,
    nst : Option<u8>,
}

impl ParamOWF {
    #[allow(clippy::too_many_arguments)]
    pub fn set_paramowf(nk : u8,
        r : u8,
        ske : u8,
        senc : u8,
        l : u16,
        lke : u16,
        lenc : u16,
        beta : u8,
        c : u16,
        nst : Option<u8>) -> ParamOWF {
            ParamOWF { nk, r, ske, senc, l, lke, lenc, beta, c, nst }
        }

    pub fn get_nk(&self) -> u8 {
        self.nk
    }

    pub fn get_r(&self) -> u8 {
        self.r
    }

    pub fn get_ske(&self) -> u8 {
        self.ske
    }

    pub fn get_senc(&self) -> u8 {
        self.senc
    }

    pub fn get_l(&self) -> u16 {
        self.l
    }

    pub fn get_lke(&self) -> u16 {
        self.lke
    }

    pub fn get_lenc(&self) -> u16 {
        self.lenc
    }

    pub fn get_beta(&self) -> u8 {
        self.beta
    }

    pub fn get_c(&self) -> u16 {
        self.c
    }

    pub fn get_nst(&self) -> u8 {
        self.nst.unwrap()
    }

    pub fn set_nk(&mut self, value : u8) {
        self.nk = value
    }

    pub fn set_r(&mut self, value : u8) {
        self.r = value
    }

    pub fn set_ske(&mut self, value : u8) {
        self.ske = value
    }

    pub fn set_senc(&mut self, value : u8) {
        self.senc = value
    }

    pub fn set_l(&mut self, value : u16) {
        self.l = value
    }

    pub fn set_lke(&mut self, value : u16) {
        self.lke = value
    }

    pub fn set_lenc(&mut self, value : u16) {
        self.lenc = value
    }

    pub fn set_beta(&mut self, value : u8) {
        self.beta = value
    }

    pub fn set_c(&mut self, value : u16) {
        self.c = value
    }

    pub fn set_nst(&mut self, value : u8){
        self.nst = Some(value)
    }

}


pub struct Param {
    lambda : u16, 
    l : u16,
    tau : u8,
    k0 : u8,
    k1: u8,
    tau0 : u8,
    tau1 : u8,
    b : u8,
    beta : u8
}


impl Param {
    #[allow(clippy::too_many_arguments)]
    pub fn set_param ( lambda : u16, 
        l : u16,
        tau : u8,
        k0 : u8,
        k1: u8,
        tau0 : u8,
        tau1 : u8,
        b : u8,
        beta : u8 ) -> Param {
            Param { lambda, l, tau, k0, k1, tau0, tau1, b, beta }
        }

    pub fn get_lambda(&self) -> u16 {
        self.lambda
    }

    pub fn get_l(&self) -> u16 {
        self.l
    }

    pub fn get_tau(&self) -> u8 {
        self.tau
    }

    pub fn get_k0(&self) -> u8 {
        self.k0
    }

    pub fn get_k1(&self) -> u8 {
        self.k1
    }

    pub fn get_tau0(&self) -> u8 {
        self.tau0
    }

    pub fn get_tau1(&self) -> u8 {
        self.tau1
    }

    pub fn get_b(&self) -> u8 {
        self.b
    }

    pub fn get_beta(&self) -> u8 {
        self.beta
    }

    pub fn set_lambda(&mut self, value : u16) {
        self.lambda = value
    }

    pub fn set_l(&mut self, value : u16) {
        self.l = value
    }

    pub fn set_tau(&mut self, value : u8){
        self.tau = value
    }

    pub fn set_k0(&mut self, value : u8){
        self.k0 = value
    }

    pub fn set_k1(&mut self, value : u8){
        self.k1 = value
    }

    pub fn set_tau0(&mut self, value : u8) {
        self.tau0 = value
    }

    pub fn set_tau1(&mut self, value : u8)  {
        self.tau1 = value
    }

    pub fn set_b(&mut self, value : u8) {
        self.b = value
    }

    pub fn set_beta(&mut self, value : u8) {
        self.beta = value
    }

}


