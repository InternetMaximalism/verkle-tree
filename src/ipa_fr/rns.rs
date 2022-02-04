use franklin_crypto::bellman::pairing::Engine;
use franklin_crypto::bellman::CurveAffine;
use franklin_crypto::plonk::circuit::bigint::field::RnsParameters;

#[warn(type_alias_bounds)]
pub type BaseRnsParameters<E> = RnsParameters<E, <<E as Engine>::G1Affine as CurveAffine>::Base>;
