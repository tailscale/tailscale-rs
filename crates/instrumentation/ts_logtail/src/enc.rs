use std::fmt::{Display, Formatter};

pub struct VarintBuf {
    buf: [u8; 20],
    len: u8
}

const HEX_CHARS: [u8; 16] = [
    b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'a', b'b', b'c', b'd', b'e', b'f',
];

impl VarintBuf {
    pub fn new() -> Self {
        VarintBuf { buf: [0; 20], len: 0 }
    }

    pub fn encode(&mut self, mut value: u64) {
        self.len = 0;

        value = value << 1;
        while value >= 0x80 {
            self.append_byte_as_hex((value & 0xFF | 0x80) as u8);
            value >>= 7;
        }
        self.append_byte_as_hex((value & 0xFF) as u8);
    }

    pub fn len(&self) -> usize {
        self.len as usize
    }

    fn append_byte_as_hex(&mut self, b: u8) {
        self.buf[self.len as usize] = HEX_CHARS[(b >> 4 & 0xF) as usize];
        self.buf[(self.len + 1) as usize] = HEX_CHARS[(b & 0xF) as usize];
        self.len += 2;
    }
}

impl Display for VarintBuf {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        // unwrap:
        f.write_str(std::str::from_utf8(&self.buf[0..self.len()]).unwrap())
    }
}