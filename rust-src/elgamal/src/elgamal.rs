use crate::constants::*;
use crate::secret::*;
use crate::public::*;
use crate::message::*;
use crate::cipher::*;
use rand::*;
use std::fmt::LowerHex;




#[test]
pub fn encrypt_decrypt(){
    let mut csprng = thread_rng();
    for _i in 1..100{
        let sk = SecretKey::generate(&mut csprng);
        println!("SK={:x}", ByteBuf(&sk.to_bytes()));
        let pk = PublicKey::from(&sk);
        println!("PK={:x}", ByteBuf(&pk.to_bytes()));
        let m = Message::generate(&mut csprng);
        println!("M={:x}", ByteBuf(&m.to_bytes()));
        let c = pk.encrypt(&mut csprng, &m);
        println!("C={:x}", ByteBuf(&c.to_bytes()));
        let t = sk.decrypt(c);
        println!("d={:x}", ByteBuf(&t.to_bytes()));
        assert_eq!(t, m);
      }
}

struct ByteBuf<'a>(&'a [u8]);

impl<'a> std::fmt::LowerHex for ByteBuf<'a> {
    fn fmt(&self, fmtr: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        for byte in self.0 {
            try!( fmtr.write_fmt(format_args!("{:02x}", byte)));
        }
        Ok(())
    }
}
