//! Types for PlatON CBFT consensus status.
//!
//! These types are used with the `debug_consensusStatus` RPC call.
//! See: https://github.com/PlatONnetwork/PlatON-Go/blob/develop/consensus/cbft/api.go

use alloy_primitives::{B256, U256};
use serde::{Deserialize, Serialize};
use alloc::{string::String, vec::Vec};


/// CBFT consensus status information.
///
/// This is the return type for the `debug_consensusStatus` RPC call on PlatON nodes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsensusStatus {
    /// The block tree structure showing fork and block relationships.
    #[serde(rename = "blockTree", skip_serializing_if = "Option::is_none")]
    pub block_tree: Option<BlockTree>,
    /// The current view state of the consensus.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<ViewState>,
    /// Whether the node is a validator.
    pub validator: bool,
}

/// Block tree structure in CBFT consensus.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockTree {
    /// The hash of the root block.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root: Option<B256>,
    /// Map of block hashes to their information.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocks: Option<Vec<BlockInfo>>,
    /// Total number of blocks in the tree.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub count: Option<u64>,
}

/// Information about a block in the CBFT block tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockInfo {
    /// Block hash.
    pub hash: B256,
    /// Block number.
    pub number: U256,
    /// Parent block hash.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_hash: Option<B256>,
    /// Whether this block is the current head.
    pub is_head: bool,
    /// Timestamp when the block was received.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receive_time: Option<u64>,
}

/// View state of CBFT consensus.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ViewState {
    /// Current view number.
    pub view_number: U256,
    /// Current block height.
    pub block_height: U256,
    /// Current block hash.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_hash: Option<B256>,
    /// Current validator set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validators: Option<Vec<ValidatorInfo>>,
    /// Next validator set (for next epoch).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_validators: Option<Vec<ValidatorInfo>>,
    /// Current epoch.
    pub epoch: U256,
}

/// Information about a validator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorInfo {
    /// Validator node ID.
    pub node_id: String,
    /// Validator address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// Stake amount.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stake: Option<U256>,
    /// Validator index in the set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index: Option<u64>,
}
