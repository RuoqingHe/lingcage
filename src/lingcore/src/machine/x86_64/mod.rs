// SPDX-FileCopyrightText: 2026 LingCage <opensource@lingcage.com>
//
// SPDX-License-Identifier: Apache-2.0

//! Assembly parts of an x86_64 guest. ACPI tables, CPUID leaves per
//! vCPU and the MP table.

/// ACPI tables in guest RAM.
pub(in crate::machine) mod acpi;
/// CPUID leaves per vCPU.
pub(in crate::machine) mod cpuid;
/// MP table in guest RAM.
pub(in crate::machine) mod mptable;
