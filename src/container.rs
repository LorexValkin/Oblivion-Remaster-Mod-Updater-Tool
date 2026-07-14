use serde::Serialize;
use std::collections::BTreeMap;

const BASE_MOUNT_ORDER: u32 = 3;

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ContainerPrecedenceWarning {
    pub package: String,
    pub winner: String,
    pub loser: String,
    pub mount_order: u32,
    pub reason: String,
}

/// Mirrors the UE pak naming rule used by Oblivion Remastered. `_P` matching
/// is case-insensitive. A numbered chunk such as `_2_P` contributes three
/// 100-point increments, producing order 303 from the normal order 3.
pub fn mount_order(container_name: &str) -> u32 {
    let lower = container_name.to_ascii_lowercase();
    let stem = lower.strip_suffix(".pak").unwrap_or(&lower);
    let Some(prefix) = stem.strip_suffix("_p") else {
        return BASE_MOUNT_ORDER;
    };
    let chunk_version = prefix
        .rsplit_once('_')
        .and_then(|(_, value)| value.parse::<u32>().ok())
        .unwrap_or(0);
    chunk_version
        .checked_add(1)
        .and_then(|value| value.checked_mul(100))
        .and_then(|value| value.checked_add(BASE_MOUNT_ORDER))
        .unwrap_or(BASE_MOUNT_ORDER + 100)
}

fn alphabetical_key(name: &str) -> (String, &str) {
    (name.to_ascii_lowercase(), name)
}

/// Warns when containers in one candidate claim the same package at the same
/// mount order. The alphabetically first name wins that IoStore tie, which is
/// the opposite of the common `zzzz_` override convention.
pub fn lint_equal_order_overrides<'a>(
    containers: impl IntoIterator<Item = (&'a str, &'a [String])>,
) -> Vec<ContainerPrecedenceWarning> {
    let mut claims: BTreeMap<String, (String, Vec<&str>)> = BTreeMap::new();
    for (container, packages) in containers {
        for package in packages {
            let normalized = package.to_ascii_lowercase();
            let claim = claims
                .entry(normalized)
                .or_insert_with(|| (package.clone(), Vec::new()));
            if !claim.1.contains(&container) {
                claim.1.push(container);
            }
        }
    }

    let mut warnings = Vec::new();
    for (_, (package, mut containers)) in claims {
        if containers.len() < 2 {
            continue;
        }
        containers.sort_by(|left, right| {
            mount_order(right)
                .cmp(&mount_order(left))
                .then_with(|| alphabetical_key(left).cmp(&alphabetical_key(right)))
        });
        let winner = containers[0];
        let winning_order = mount_order(winner);
        for loser in containers.into_iter().skip(1) {
            if mount_order(loser) != winning_order {
                continue;
            }
            warnings.push(ContainerPrecedenceWarning {
                package: package.clone(),
                winner: winner.to_owned(),
                loser: loser.to_owned(),
                mount_order: winning_order,
                reason: format!(
                    "{loser} loses this equal-order IoStore package claim to alphabetically earlier {winner}; rename the intended override to sort first (for example, AAAA_) or give it an explicitly stronger mount suffix"
                ),
            });
        }
    }
    warnings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn p_suffix_is_case_insensitive_and_numbered_chunks_are_stronger() {
        assert_eq!(mount_order("OffhandStaves_p"), 103);
        assert_eq!(mount_order("Override_P.pak"), 103);
        assert_eq!(mount_order("Override_2_P"), 303);
        assert_eq!(mount_order("ordinary"), 3);
    }

    #[test]
    fn catches_the_offhand_staves_equal_order_precedence_trap() {
        let original = vec!["/Game/Art/Equipment/armor/SM_Offhand_Staff".to_owned()];
        let recook = vec!["/game/art/equipment/armor/sm_offhand_staff".to_owned()];
        let warnings = lint_equal_order_overrides([
            ("OffhandStaves_p", original.as_slice()),
            ("zzzz_OffhandStaves_NativePhysics_P", recook.as_slice()),
        ]);
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].winner, "OffhandStaves_p");
        assert_eq!(warnings[0].loser, "zzzz_OffhandStaves_NativePhysics_P");
        assert_eq!(warnings[0].mount_order, 103);
    }

    #[test]
    fn alphabetically_first_override_wins_without_a_warning_for_it() {
        let packages = vec!["/Game/Shared".to_owned()];
        let warnings = lint_equal_order_overrides([
            ("OffhandStaves_p", packages.as_slice()),
            ("AAAA_OffhandStaves_NativePhysics_P", packages.as_slice()),
        ]);
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].winner, "AAAA_OffhandStaves_NativePhysics_P");
        assert_eq!(warnings[0].loser, "OffhandStaves_p");
    }

    #[test]
    fn stronger_mount_order_is_not_an_equal_order_naming_warning() {
        let packages = vec!["/Game/Shared".to_owned()];
        let warnings = lint_equal_order_overrides([
            ("AAAA_Original_P", packages.as_slice()),
            ("zzzz_Override_2_P", packages.as_slice()),
        ]);
        assert!(warnings.is_empty());
    }
}
