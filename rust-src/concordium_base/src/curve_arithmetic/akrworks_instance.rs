#[allow(unused_imports)]
use ark_ff;
#[allow(unused_imports)]
use ff;

// Potentially, we could provide a blanket implementation of `ff:Field` that we
// use in our code for any instance of `ark_ff::Field`, but both packeges are
// external, so we cannot do it here.

// impl<F: ark_ff::Field> ff::Field for F {
//     fn random<R: rand_core::RngCore + ?std::marker::Sized>(rng: &mut R) ->
// Self {         todo!()
//     }

//     fn zero() -> Self {
//         ark_ff::Field::ZERO
//     }

//     fn one() -> Self {
//         ark_ff::Field::ONE
//     }

//     fn is_zero(&self) -> bool {
//         self.is_zero()
//     }

//     fn square(&mut self) {
//         self.square_in_place()
//     }

//     fn double(&mut self) {
//         self.double_in_place()
//     }

//     fn negate(&mut self) {
//         self.neg_in_place()
//     }

//     fn add_assign(&mut self, other: &Self) {
//         self.add_assign(other)
//     }

//     fn sub_assign(&mut self, other: &Self) {
//         self.sub_assign(other)
//     }

//     fn mul_assign(&mut self, other: &Self) {
//         self.mul_assign(other)
//     }

//     fn inverse(&self) -> Option<Self> {
//         ark_ff::Field::inverse(&self)
//     }

//     fn frobenius_map(&mut self, power: usize) {
//         ark_ff::Field::frobenius_map(&self, power)
//     }
// }
