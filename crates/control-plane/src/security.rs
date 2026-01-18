use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use bitflags::bitflags;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct Sid(pub String);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupSid {
    pub sid: Sid,
    pub attributes: GroupAttributes,
}

bitflags! {
    #[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
    pub struct GroupAttributes: u32 {
        const ENABLED = 0b0001;
        const DENY_ONLY = 0b0010;
        const MANDATORY = 0b0100;
        const OWNER = 0b1000;
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Privilege {
    pub name: String,
    pub enabled: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub enum IntegrityLevel {
    Low,
    Medium,
    High,
    System,
}

bitflags! {
    #[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
    pub struct TokenFlags: u32 {
        const DENY_ONLY = 0b0001;
        const SANDBOXED = 0b0010;
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecurityToken {
    pub token_id: String,
    pub user_sid: Sid,
    pub group_sids: Vec<GroupSid>,
    pub restricted_sids: Vec<Sid>,
    pub privileges: Vec<Privilege>,
    pub integrity_level: IntegrityLevel,
    pub claims: HashMap<String, String>,
    pub flags: TokenFlags,
}

bitflags! {
    #[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
    pub struct AccessMask: u32 {
        const READ = 0b0000_0001;
        const USE = 0b0000_0010;
        const MANAGE = 0b0000_0100;
        const ADMIN = 0b0000_1000;
        const PROVIDER_USE = 0b0001_0000;
        const PROVIDER_MANAGE = 0b0010_0000;
        const KEY_USE = 0b0100_0000;
        const KEY_MANAGE = 0b1000_0000;
        const ADDRESS_USE = 0b0001_0000_0000;
        const ADDRESS_MANAGE = 0b0010_0000_0000;
        const MODEL_USE = 0b0100_0000_0000;
        const TOOL_USE = 0b1000_0000_0000;
        const SESSION_BIND = 0b0001_0000_0000_0000;
        const SESSION_READ = 0b0010_0000_0000_0000;
        const CONFIG_READ = 0b0100_0000_0000_0000;
        const CONFIG_WRITE = 0b1000_0000_0000_0000;
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClaimPredicate {
    pub key: String,
    pub value: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AceType {
    Allow,
    Deny,
    Audit,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Ace {
    pub ace_type: AceType,
    pub sid: Sid,
    pub access_mask: AccessMask,
    pub condition: Option<ClaimPredicate>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecurityDescriptor {
    pub owner_sid: Sid,
    pub group_sid: Sid,
    pub dacl: Vec<Ace>,
    pub sacl: Vec<Ace>,
    pub mandatory_label: IntegrityLevel,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccessCheckConfig {
    pub privilege_overrides: HashMap<String, AccessMask>,
}

impl Default for AccessCheckConfig {
    fn default() -> Self {
        Self {
            privilege_overrides: HashMap::new(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum AccessDecision {
    Allow,
    Deny,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenRecord {
    pub token_key: String,
    pub token: SecurityToken,
}

pub trait AccessCheckEngine: Send + Sync {
    fn check(&self, token: &SecurityToken, descriptor: &SecurityDescriptor, access: AccessMask)
        -> AccessDecision;
}

pub struct AccessChecker {
    config: AccessCheckConfig,
}

impl AccessChecker {
    pub fn new(config: AccessCheckConfig) -> Self {
        Self { config }
    }

    fn satisfies_integrity(&self, token: &SecurityToken, descriptor: &SecurityDescriptor) -> bool {
        token.integrity_level >= descriptor.mandatory_label
    }

    fn claim_matches(token: &SecurityToken, predicate: &Option<ClaimPredicate>) -> bool {
        match predicate {
            None => true,
            Some(pred) => token.claims.get(&pred.key) == Some(&pred.value),
        }
    }

    fn effective_sids(token: &SecurityToken) -> HashSet<Sid> {
        let mut sids = HashSet::new();
        sids.insert(token.user_sid.clone());
        for group in &token.group_sids {
            if group.attributes.contains(GroupAttributes::ENABLED)
                && !group.attributes.contains(GroupAttributes::DENY_ONLY)
            {
                sids.insert(group.sid.clone());
            }
        }
        sids
    }

    fn deny_sids(token: &SecurityToken) -> HashSet<Sid> {
        let mut sids = HashSet::new();
        sids.insert(token.user_sid.clone());
        for group in &token.group_sids {
            sids.insert(group.sid.clone());
        }
        sids
    }

    fn privilege_mask(&self, token: &SecurityToken) -> AccessMask {
        let mut mask = AccessMask::empty();
        for privilege in &token.privileges {
            if !privilege.enabled {
                continue;
            }
            if let Some(extra) = self.config.privilege_overrides.get(&privilege.name) {
                mask |= *extra;
            }
        }
        mask
    }

    fn allow_mask_for_sids(
        &self,
        descriptor: &SecurityDescriptor,
        sids: &HashSet<Sid>,
        token: &SecurityToken,
    ) -> AccessMask {
        let mut allowed = AccessMask::empty();
        for ace in &descriptor.dacl {
            match ace.ace_type {
                AceType::Allow => {
                    if sids.contains(&ace.sid) && Self::claim_matches(token, &ace.condition) {
                        allowed |= ace.access_mask;
                    }
                }
                _ => {}
            }
        }
        allowed
    }
}

impl AccessCheckEngine for AccessChecker {
    fn check(
        &self,
        token: &SecurityToken,
        descriptor: &SecurityDescriptor,
        access: AccessMask,
    ) -> AccessDecision {
        if !self.satisfies_integrity(token, descriptor) {
            return AccessDecision::Deny;
        }

        let deny_sids = Self::deny_sids(token);
        for ace in &descriptor.dacl {
            if let AceType::Deny = ace.ace_type {
                if deny_sids.contains(&ace.sid)
                    && ace.access_mask.intersects(access)
                    && Self::claim_matches(token, &ace.condition)
                {
                    return AccessDecision::Deny;
                }
            }
        }

        let mut allowed_mask = self.allow_mask_for_sids(descriptor, &Self::effective_sids(token), token);
        allowed_mask |= self.privilege_mask(token);

        if !allowed_mask.contains(access) {
            return AccessDecision::Deny;
        }

        if !token.restricted_sids.is_empty() {
            let restricted: HashSet<Sid> = token.restricted_sids.iter().cloned().collect();
            let restricted_mask = self.allow_mask_for_sids(descriptor, &restricted, token);
            if !restricted_mask.contains(access) {
                return AccessDecision::Deny;
            }
        }

        AccessDecision::Allow
    }
}

pub trait SecurityAuthority: Send + Sync {
    fn authenticate(&self, token_key: Option<&str>) -> Option<SecurityToken>;
}

pub struct StaticSecurityAuthority {
    tokens: HashMap<String, SecurityToken>,
}

impl StaticSecurityAuthority {
    pub fn new(tokens: HashMap<String, SecurityToken>) -> Self {
        Self { tokens }
    }

    pub fn shared(tokens: HashMap<String, SecurityToken>) -> Arc<Self> {
        Arc::new(Self::new(tokens))
    }
}

impl SecurityAuthority for StaticSecurityAuthority {
    fn authenticate(&self, token_key: Option<&str>) -> Option<SecurityToken> {
        let key = token_key?;
        self.tokens.get(key).cloned()
    }
}
