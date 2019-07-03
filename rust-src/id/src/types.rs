use curve_arithmetic::curve_arithmetic::*;
use curve_arithmetic::curve_arithmetic::FieldDecodingError;
use curve_arithmetic::bls12_381_instance::*;
use pairing::bls12_381::{Bls12, Fr, FrRepr};
use pairing::{Field, PrimeField};
use ps_sig::{signature::*, ps_sig_scheme::*};
use chrono::{NaiveDate, NaiveDateTime};


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

struct AttributeList ([KnownAttributes;5]);

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

struct IdCredentials<C:Curve>{
    id_cred_sec: C::Scalar,
    id_cred_pub: C
}

struct AccHolderInfo<P:Pairing>{
    id_ah: String,
    id_cred: IdCredentials<P::G_2>,
    //aux_data: &[u8]

}

struct AccCredentialInfo<P:Pairing, A: Attributes<P::ScalarField>>{
    acc_holder_info: AccHolderInfo<P>,
    prf_key: P::ScalarField,
    attritubtes: A

}
struct CredDeploymentCert<P:Pairing, A: Attributes<P::ScalarField>> { 
    acc_credential_info: AccCredentialInfo<P, A>,
    id_ip: String,
    sig: Signature<P>,

}
/*
struct ArData<P:Pairing>{
    ar_name: String,
    e_reg_id: Cipher  
    
}
*/
struct CredDeploymentInfo<P:Pairing, A: Attributes<P::ScalarField>>{
    reg_id : P::G_1,
    attributes: A

}

    




