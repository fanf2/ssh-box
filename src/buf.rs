pub struct Buf(Vec<u8>);

impl Buf {
    pub fn new() -> Self {
        Buf(Vec::new())
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }

    pub fn as_ref(&self) -> &[u8] {
        &self.0
    }

    pub fn add_byte(&mut self, byte: u8) {
        self.0.push(byte);
    }

    pub fn add_bytes(&mut self, bytes: &[u8]) {
        self.0.extend_from_slice(bytes);
    }

    pub fn add_u32(&mut self, n: u32) {
        self.add_bytes(&n.to_be_bytes());
    }

    pub fn add_string(&mut self, string: &[u8]) {
        self.add_u32(string.len() as u32);
        self.add_bytes(string);
    }

    pub fn add_strings(&mut self, strings: &[Vec<u8>]) {
        for s in strings {
            self.add_string(s)
        }
    }
}
