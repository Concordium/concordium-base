use curve_arithmetic::curve_arithmetic::*;
use curve_arithmetic::curve_arithmetic::FieldDecodingError;
use pairing::bls12_381::{Bls12, Fr, FrRepr};
use pairing::{Field, PrimeField};
use ps_sig::signature::* ;
use chrono::{NaiveDateTime};


pub trait Attribute<F:Field> {
    fn to_field_element(&self) -> Result<F,FieldDecodingError>;
}

pub enum KnownAttributes{
    Age(u8),
    Citizenship(u16),
    ExpiryDate(NaiveDateTime)
}

impl Attribute<<Bls12 as Pairing>::ScalarField> for KnownAttributes{
    fn to_field_element(&self) -> Result<<Bls12 as Pairing>::ScalarField, FieldDecodingError> {
        match self {
            KnownAttributes::Age(x) => {let f = Fr::from_repr(FrRepr::from(*x as u64))?; Ok(f)},
            KnownAttributes::Citizenship(c) => {let f = Fr::from_repr(FrRepr::from(*c as u64))?; Ok(f)},
            KnownAttributes::ExpiryDate(date) => { if date.timestamp() < 0 {
                Err(FieldDecodingError::NotFieldElement)
            } else{
                let f = Fr::from_repr(FrRepr::from(date.timestamp() as u64))?; Ok(f)}
            }
        }
    }
}

pub trait Attributes<F:Field>{
    type AttributeType: Attribute<F>;
    const VERSION: u32;
    fn index(a: &Self::AttributeType) -> u32;  
}

pub struct AttributeList ([KnownAttributes;5]);

impl Attributes<<Bls12 as Pairing>::ScalarField> for AttributeList{
    type AttributeType = KnownAttributes;
    const VERSION: u32 = 0;
    fn index(a: &KnownAttributes) -> u32{
        match a {
            KnownAttributes::Age(_x) => 2,
            KnownAttributes::Citizenship(_x) => 3,
            KnownAttributes::ExpiryDate(_x) => 4
        }
    }
}

pub struct IdCredentials<C:Curve>{
    pub id_cred_sec: C::Scalar,
    pub id_cred_pub: C
}

pub struct AccHolderInfo<P:Pairing>{
    pub id_ah: String,
    pub id_cred: IdCredentials<P::G_2>,
    //aux_data: &[u8]

}

pub struct AccCredentialInfo<P:Pairing, A: Attributes<P::ScalarField>>{
    pub acc_holder_info: AccHolderInfo<P>,
    pub prf_key: P::ScalarField,
    pub attritubtes: A

}
pub struct CredDeploymentCert<P:Pairing, A: Attributes<P::ScalarField>> { 
    pub acc_credential_info: AccCredentialInfo<P, A>,
    pub id_ip: String,
    pub usig: Signature<P>,

}
/*
struct ArData<P:Pairing>{
    ar_name: String,
    e_reg_id: Cipher  
    
}
*/
pub struct CredDeploymentInfo<P:Pairing, A: Attributes<P::ScalarField>>{
    pub reg_id : P::G_1,
    pub attributes: A

}

    




