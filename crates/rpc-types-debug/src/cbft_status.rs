//! CBFT consensus status types for PlatON's `debug_consensusStatus` RPC.
//!
//! These types represent the response from PlatON's CBFT consensus status endpoint.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use alloy_primitives::B256;
use serde::{Deserialize, Serialize};

/// Response type for `debug_consensusStatus` RPC call.
///
/// Contains the current CBFT consensus status including block tree,
/// view state, and validator information.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsensusStatus {
    /// Block tree structure.
    #[serde(default)]
    pub block_tree: BlockTree,
    /// Current view state.
    #[serde(default)]
    pub state: ViewState,
    /// Whether this node is a validator.
    #[serde(default)]
    pub validator: bool,
}

/// Block tree structure in CBFT consensus.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct BlockTree {
    /// Blocks grouped by block number, then indexed by hash.
    #[serde(default)]
    pub blocks: BTreeMap<u64, BTreeMap<B256, serde_json::Value>>,
    /// Root block information.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root: Option<RootBlockInfo>,
}

/// Root block information in the block tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RootBlockInfo {
    /// Block hash.
    pub block_hash: B256,
    /// Block number.
    pub block_number: u64,
    /// Hashes of child blocks.
    #[serde(default)]
    pub children_hash: Vec<B256>,
    /// Parent block hash.
    pub parent_hash: B256,
    /// Quorum certificate for this block.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub qc: Option<QuorumCert>,
    /// Time when this block was received.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receive_time: Option<serde_json::Value>,
    /// View number.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub view_number: Option<u64>,
}

/// Quorum certificate for a block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QuorumCert {
    /// Block hash.
    pub block_hash: B256,
    /// Block index within the epoch.
    pub block_index: u32,
    /// Block number.
    pub block_number: u64,
    /// Epoch number.
    pub epoch: u64,
    /// Aggregated signature.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<serde_json::Value>,
    /// Validator set bitmask.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validator_set: Option<serde_json::Value>,
    /// View number.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub view_number: Option<u64>,
}

/// View state in CBFT consensus.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ViewState {
    /// Current view information.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub view: Option<View>,
    /// Highest QC block.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub highest_qc_block: Option<HashNumber>,
    /// Highest locked block.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub highest_lock_block: Option<HashNumber>,
    /// Highest committed block.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub highest_commit_block: Option<HashNumber>,
}

/// Hash and number pair for block identification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HashNumber {
    /// Block hash.
    pub hash: B256,
    /// Block number.
    pub number: u64,
}

/// View information in CBFT consensus.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct View {
    /// Epoch number.
    pub epoch: u64,
    /// View number.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub view_number: Option<u64>,
    /// Current execution state.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executing: Option<Executing>,
    /// View change messages received.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub viewchange: Option<ViewChanges>,
    /// Last view change QC.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_viewchange: Option<serde_json::Value>,
    /// Prepare votes that have been sent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub had_send_prepare_vote: Option<PrepareVoteQueue>,
    /// Pending prepare votes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pending_prepare_vote: Option<PrepareVoteQueue>,
    /// Blocks proposed in this view.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub view_blocks: Option<ViewBlocks>,
    /// QCs in this view.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub view_qcs: Option<ViewQCs>,
    /// Votes received in this view.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub view_votes: Option<ViewVotes>,
}

/// Current execution state within a view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Executing {
    /// Block index being executed (4294967295 = u32::MAX means none).
    #[serde(default)]
    pub block_index: u32,
    /// Whether execution is finished.
    #[serde(default)]
    pub finish: bool,
}

/// Queue of prepare votes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrepareVoteQueue {
    /// List of votes.
    #[serde(default)]
    pub votes: Vec<serde_json::Value>,
}

/// Blocks proposed in a view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ViewBlocks {
    /// Blocks indexed by block index.
    #[serde(default)]
    pub blocks: BTreeMap<u32, ViewBlockInfo>,
}

/// Information about a block in the view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ViewBlockInfo {
    /// Block hash.
    pub hash: B256,
    /// Block number.
    pub number: u64,
    /// Block index within the view.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_index: Option<u32>,
}

/// Quorum certificates in a view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ViewQCs {
    /// Maximum block index with a QC.
    #[serde(default)]
    pub max_index: u32,
    /// QCs indexed by block index.
    #[serde(default)]
    pub qcs: BTreeMap<u32, QuorumCert>,
}

/// Votes received in a view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ViewVotes {
    /// Votes indexed by block index.
    #[serde(default)]
    pub votes: BTreeMap<u32, PrepareVotes>,
}

/// Prepare votes for a specific block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrepareVotes {
    /// Votes indexed by validator index.
    #[serde(default)]
    pub votes: BTreeMap<u32, serde_json::Value>,
}

/// View change messages.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ViewChanges {
    /// View changes indexed by validator index.
    #[serde(default)]
    pub viewchanges: BTreeMap<u32, serde_json::Value>,
}
