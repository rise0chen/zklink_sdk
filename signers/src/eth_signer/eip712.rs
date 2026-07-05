use crate::eth_signer::error::EthSignerError;
use alloy::primitives::{Address, B256, U256};
use alloy::sol_types::{Eip712Domain, SolStruct};
use serde::{Deserialize, Serialize};
use std::ops::{Deref, DerefMut};
use std::str::FromStr;

///
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EIP712Domain {
    #[serde(flatten)]
    inner: Eip712Domain,
}

impl EIP712Domain {
    pub fn new(
        name: String,
        version: String,
        layer_one_chain_id: u32,
        eth_contract_addr: String,
    ) -> Result<Self, EthSignerError> {
        let verifying_contract = Address::from_str(eth_contract_addr.as_str())
            .map_err(|e| EthSignerError::Eip712Failed(e.to_string()))?;
        let domain = Eip712Domain {
            name: Some(name.into()),
            version: Some(version.into()),
            chain_id: Some(U256::from(layer_one_chain_id)),
            verifying_contract: Some(verifying_contract),
            salt: None,
        };
        Ok(Self { inner: domain })
    }

    pub fn new_zklink_domain(
        layer_one_chain_id: u32,
        eth_contract_addr: String,
    ) -> Result<Self, EthSignerError> {
        EIP712Domain::new(
            "ZkLink".into(),
            "1".into(),
            layer_one_chain_id,
            eth_contract_addr,
        )
    }
}
impl Deref for EIP712Domain {
    type Target = Eip712Domain;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}
impl DerefMut for EIP712Domain {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TypedData {
    #[serde(flatten)]
    inner: alloy::dyn_abi::TypedData,
}

impl TypedData {
    /// Create eth_signTypedData payload.
    pub fn new<M: SolStruct + Serialize>(
        domain: EIP712Domain,
        value: M,
    ) -> Result<TypedData, EthSignerError> {
        let inner = alloy::dyn_abi::TypedData::from_struct(&value, Some(domain.inner));

        Ok(TypedData { inner })
    }
    pub fn sign_hash(&self) -> Result<B256, EthSignerError> {
        self.inner
            .eip712_signing_hash()
            .map_err(|e| EthSignerError::Eip712Failed(e.to_string()))
    }
}
impl Deref for TypedData {
    type Target = alloy::dyn_abi::TypedData;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}
impl DerefMut for TypedData {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}
