// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Request of a sandbox from caller, plain data parsed by CLI and
//! checked by admission, separate from the running one.

use std::collections::BTreeMap;

use crate::template::{Template, TemplateId};

/// Sandbox to start, with template, limits and labels.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SandboxSpec {
    /// Template to clone.
    pub template: TemplateId,
    /// Resource bounds. `memory` and `vcpus` should match the shape of the
    /// template, caller states them explicitly so that the constraint is
    /// visible instead of failing at spawn time.
    pub limits: Limits,
    /// Labels from caller. `hostname` is used as guest hostname if present.
    pub labels: BTreeMap<String, String>,
}

impl SandboxSpec {
    /// Spec matching the shape of `template`, without labels.
    pub fn for_template(template: &Template) -> SandboxSpec {
        let shape = &template.meta().shape;
        SandboxSpec {
            template: template.id().clone(),
            limits: Limits {
                memory: shape.memory,
                vcpus: shape.vcpus,
            },
            labels: BTreeMap::new(),
        }
    }

    /// Set guest hostname to `hostname`.
    pub fn hostname(mut self, hostname: impl Into<String>) -> SandboxSpec {
        self.labels.insert("hostname".to_string(), hostname.into());
        self
    }
}

/// Resource bounds of a sandbox.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Limits {
    /// Guest RAM size in bytes.
    pub memory: u64,
    /// Number of vCPUs.
    pub vcpus: u16,
}

impl std::fmt::Display for Limits {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} bytes, {} vcpus", self.memory, self.vcpus)
    }
}

#[cfg(test)]
mod tests {
    use crate::sandbox::spec::*;

    #[test]
    fn test_spec_json_round_trip() {
        let spec = SandboxSpec {
            template: TemplateId::from("base"),
            limits: Limits {
                memory: 512 << 20,
                vcpus: 2,
            },
            labels: BTreeMap::from([("hostname".to_string(), "worker".to_string())]),
        };
        let text = serde_json::to_string(&spec).expect("code the spec");
        let back: SandboxSpec = serde_json::from_str(&text).expect("decode the spec");
        assert_eq!(back.template, spec.template);
        assert_eq!(back.limits, spec.limits);
        assert_eq!(back.labels, spec.labels);
    }

    #[test]
    fn test_limits_display() {
        let limits = Limits {
            memory: 1024,
            vcpus: 3,
        };
        assert_eq!(limits.to_string(), "1024 bytes, 3 vcpus");
    }
}
