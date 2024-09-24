/// Reader interface for PRGs and random oracles
pub trait Reader {
    /// Read bytes from PRG/random oracle
    fn read(&mut self, dst: &mut [u8]);
}
