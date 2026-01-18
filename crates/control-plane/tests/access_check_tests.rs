use std::collections::HashMap;

use control_plane::{
    AccessCheckConfig, AccessCheckEngine, AccessChecker, AccessDecision, AccessMask, Ace, AceType,
    ClaimPredicate, GroupAttributes, GroupSid, IntegrityLevel, Privilege, SecurityDescriptor,
    SecurityToken, Sid, TokenFlags,
};

fn base_token() -> SecurityToken {
    SecurityToken {
        token_id: "t1".to_string(),
        user_sid: Sid("user".to_string()),
        group_sids: vec![GroupSid {
            sid: Sid("group".to_string()),
            attributes: GroupAttributes::ENABLED,
        }],
        restricted_sids: Vec::new(),
        privileges: vec![Privilege {
            name: "override".to_string(),
            enabled: true,
        }],
        integrity_level: IntegrityLevel::Medium,
        claims: HashMap::new(),
        flags: TokenFlags::empty(),
    }
}

fn base_descriptor(aces: Vec<Ace>) -> SecurityDescriptor {
    SecurityDescriptor {
        owner_sid: Sid("owner".to_string()),
        group_sid: Sid("group".to_string()),
        dacl: aces,
        sacl: Vec::new(),
        mandatory_label: IntegrityLevel::Low,
    }
}

#[test]
fn allow_ace_grants_access() {
    let token = base_token();
    let desc = base_descriptor(vec![Ace {
        ace_type: AceType::Allow,
        sid: Sid("user".to_string()),
        access_mask: AccessMask::USE,
        condition: None,
    }]);
    let checker = AccessChecker::new(AccessCheckConfig::default());
    let decision = checker.check(&token, &desc, AccessMask::USE);
    assert_eq!(decision, AccessDecision::Allow);
}

#[test]
fn deny_ace_blocks_access() {
    let token = base_token();
    let desc = base_descriptor(vec![
        Ace {
            ace_type: AceType::Allow,
            sid: Sid("user".to_string()),
            access_mask: AccessMask::USE,
            condition: None,
        },
        Ace {
            ace_type: AceType::Deny,
            sid: Sid("group".to_string()),
            access_mask: AccessMask::USE,
            condition: None,
        },
    ]);
    let checker = AccessChecker::new(AccessCheckConfig::default());
    let decision = checker.check(&token, &desc, AccessMask::USE);
    assert_eq!(decision, AccessDecision::Deny);
}

#[test]
fn mandatory_label_blocks_low_integrity() {
    let token = base_token();
    let mut desc = base_descriptor(Vec::new());
    desc.mandatory_label = IntegrityLevel::High;
    let checker = AccessChecker::new(AccessCheckConfig::default());
    let decision = checker.check(&token, &desc, AccessMask::USE);
    assert_eq!(decision, AccessDecision::Deny);
}

#[test]
fn restricted_token_requires_dual_allow() {
    let mut token = base_token();
    token.restricted_sids = vec![Sid("restricted".to_string())];
    let desc = base_descriptor(vec![
        Ace {
            ace_type: AceType::Allow,
            sid: Sid("user".to_string()),
            access_mask: AccessMask::USE,
            condition: None,
        },
        Ace {
            ace_type: AceType::Allow,
            sid: Sid("restricted".to_string()),
            access_mask: AccessMask::USE,
            condition: None,
        },
    ]);
    let checker = AccessChecker::new(AccessCheckConfig::default());
    let decision = checker.check(&token, &desc, AccessMask::USE);
    assert_eq!(decision, AccessDecision::Allow);
}

#[test]
fn restricted_token_denies_without_restricted_allow() {
    let mut token = base_token();
    token.restricted_sids = vec![Sid("restricted".to_string())];
    let desc = base_descriptor(vec![Ace {
        ace_type: AceType::Allow,
        sid: Sid("user".to_string()),
        access_mask: AccessMask::USE,
        condition: None,
    }]);
    let checker = AccessChecker::new(AccessCheckConfig::default());
    let decision = checker.check(&token, &desc, AccessMask::USE);
    assert_eq!(decision, AccessDecision::Deny);
}

#[test]
fn claim_predicate_required() {
    let mut token = base_token();
    token
        .claims
        .insert("region".to_string(), "cn".to_string());
    let desc = base_descriptor(vec![Ace {
        ace_type: AceType::Allow,
        sid: Sid("user".to_string()),
        access_mask: AccessMask::USE,
        condition: Some(ClaimPredicate {
            key: "region".to_string(),
            value: "cn".to_string(),
        }),
    }]);
    let checker = AccessChecker::new(AccessCheckConfig::default());
    let decision = checker.check(&token, &desc, AccessMask::USE);
    assert_eq!(decision, AccessDecision::Allow);
}
