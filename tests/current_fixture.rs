use obr_mod_updater::engine::{UpdateRequest, run_update};
use obr_mod_updater::replacement::probe_composite_package_input;
use std::path::PathBuf;

#[test]
#[ignore = "requires an installed game and local fixture archives"]
fn updates_current_offhand_staves_fixture() {
    let required = |name: &str| {
        std::env::var_os(name)
            .map(PathBuf::from)
            .unwrap_or_else(|| panic!("missing required test environment variable {name}"))
    };
    let dependency = std::env::var_os("OBR_TEST_DEPENDENCY")
        .map(PathBuf::from)
        .into_iter()
        .collect();
    let expected_package_count = std::env::var("OBR_TEST_ADDITIVE_PACKAGE_COUNT")
        .ok()
        .map(|value| {
            value
                .parse::<usize>()
                .expect("invalid OBR_TEST_ADDITIVE_PACKAGE_COUNT")
        })
        .unwrap_or(6);
    let expected_body_setup_repair_count =
        std::env::var("OBR_TEST_ADDITIVE_BODY_SETUP_REPAIR_COUNT")
            .ok()
            .map(|value| {
                value
                    .parse::<usize>()
                    .expect("invalid OBR_TEST_ADDITIVE_BODY_SETUP_REPAIR_COUNT")
            })
            .unwrap_or(2);
    let mut log = Vec::new();
    let outcome = run_update(
        UpdateRequest {
            adapter: "native-additive-syncmap-v1".to_owned(),
            mod_input: required("OBR_TEST_MOD"),
            game_root: required("OBR_TEST_GAME"),
            output_parent: required("OBR_TEST_OUTPUT"),
            dependency_inputs: dependency,
            installed_collision_exclusions: Vec::new(),
            persist_settings: false,
        },
        &mut |step, total, message| log.push(format!("[{step}/{total}] {message}")),
    )
    .unwrap_or_else(|error| panic!("native update failed:\n{error:#}\n{}", log.join("\n")));
    assert!(outcome.output_archive.is_file());
    assert!(outcome.report_path.is_file());
    assert_eq!(outcome.package_count, expected_package_count);
    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(outcome.report_path).unwrap()).unwrap();
    assert_eq!(report["implementation"], "native-rust");
    assert_eq!(report["version"], 6);
    assert_eq!(
        report["fixApis"],
        serde_json::json!([
            "zen-dependency-trace-v1",
            "zen-exact-dependency-extraction-v1",
            "zen-dependency-preservation-v1"
        ])
    );
    assert_eq!(report["identity"]["espBytePreserved"], true);
    assert_eq!(report["unreal"]["targetPathCollisionCount"], 0);
    assert_eq!(
        report["verification"]["packageDependencyGraphsPreserved"],
        true
    );
    assert_eq!(report["verification"]["dependencyCompleteExtraction"], true);
    assert!(
        report["unreal"]["containers"]
            .as_array()
            .unwrap()
            .iter()
            .all(|container| {
                container["exactExtraction"]["packageCount"] == container["packageCount"]
                    && container["dependencyPreservation"]["preserved"] == true
            })
    );
    assert_eq!(
        report["unreal"]["bodySetupRepairCount"],
        expected_body_setup_repair_count
    );
    assert_eq!(report["unreal"]["containerNaming"]["warningCount"], 0);
    let repairs = report["unreal"]["containers"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|container| container["bodySetupRepairs"].as_array().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(repairs.len(), expected_body_setup_repair_count);
    assert!(
        repairs
            .iter()
            .all(|repair| repair["collisionRemoved"] == true)
    );
}

#[test]
#[ignore = "requires an installed game and a local composite-package fixture"]
fn probes_current_composite_package_fixture() {
    let required = |name: &str| {
        std::env::var_os(name)
            .map(PathBuf::from)
            .unwrap_or_else(|| panic!("missing required test environment variable {name}"))
    };
    let summary = probe_composite_package_input(
        &required("OBR_TEST_COMPOSITE_MOD"),
        &required("OBR_TEST_GAME"),
    )
    .unwrap();
    assert!(summary.container_count > 0);
    assert!(summary.package_count > 0);
    assert!(summary.asset_kind.starts_with("composite-package-rebase"));
}

#[test]
#[ignore = "requires an installed game and a local composite-package fixture"]
fn updates_current_composite_package_fixture() {
    let required = |name: &str| {
        std::env::var_os(name)
            .map(PathBuf::from)
            .unwrap_or_else(|| panic!("missing required test environment variable {name}"))
    };
    let mut log = Vec::new();
    let collision_exclusions = std::env::var_os("OBR_TEST_COMPOSITE_COLLISION_EXCLUSIONS")
        .map(|value| {
            value
                .to_string_lossy()
                .split(';')
                .filter(|path| !path.trim().is_empty())
                .map(PathBuf::from)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let outcome = run_update(
        UpdateRequest {
            adapter: "native-composite-package-rebase-v1".to_owned(),
            mod_input: required("OBR_TEST_COMPOSITE_MOD"),
            game_root: required("OBR_TEST_GAME"),
            output_parent: required("OBR_TEST_OUTPUT"),
            dependency_inputs: Vec::new(),
            installed_collision_exclusions: collision_exclusions,
            persist_settings: false,
        },
        &mut |step, total, message| log.push(format!("[{step}/{total}] {message}")),
    )
    .unwrap_or_else(|error| panic!("composite update failed:\n{error:#}\n{}", log.join("\n")));
    assert_eq!(outcome.adapter, "native-composite-package-rebase-v1");
    assert!(outcome.output_archive.is_file());
    assert!(outcome.report_path.is_file());
    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(outcome.report_path).unwrap()).unwrap();
    assert_eq!(report["structurallyVerified"], true);
    assert_eq!(report["runtimeVerified"], false);
    assert_eq!(report["identity"]["classDrivenSystemWideRules"], true);
    assert_eq!(report["identity"]["modSpecificWhitelistUsed"], false);
    assert_eq!(
        report["verification"]["approvedExportPayloadMigrationPreserved"],
        true
    );
}

#[test]
#[ignore = "requires an installed game and a local armor-replacement fixture"]
fn updates_current_armor_replacement_fixture() {
    let required = |name: &str| {
        std::env::var_os(name)
            .map(PathBuf::from)
            .unwrap_or_else(|| panic!("missing required test environment variable {name}"))
    };
    let mut log = Vec::new();
    let expected_package_count = std::env::var("OBR_TEST_ARMOR_PACKAGE_COUNT")
        .ok()
        .map(|value| {
            value
                .parse::<usize>()
                .expect("invalid OBR_TEST_ARMOR_PACKAGE_COUNT")
        })
        .unwrap_or(6);
    let outcome = run_update(
        UpdateRequest {
            adapter: "native-armor-replacement-v1".to_owned(),
            mod_input: required("OBR_TEST_ARMOR_MOD"),
            game_root: required("OBR_TEST_GAME"),
            output_parent: required("OBR_TEST_OUTPUT"),
            dependency_inputs: Vec::new(),
            installed_collision_exclusions: std::env::var_os("OBR_TEST_COLLISION_EXCLUSION")
                .map(PathBuf::from)
                .into_iter()
                .collect(),
            persist_settings: false,
        },
        &mut |step, total, message| log.push(format!("[{step}/{total}] {message}")),
    )
    .unwrap_or_else(|error| {
        panic!(
            "armor replacement update failed:\n{error:#}\n{}",
            log.join("\n")
        )
    });
    assert!(outcome.output_archive.is_file());
    assert!(outcome.report_path.is_file());
    assert_eq!(outcome.adapter, "native-armor-replacement-v1");
    assert_eq!(outcome.package_count, expected_package_count);
    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(outcome.report_path).unwrap()).unwrap();
    assert_eq!(report["adapter"], "native-armor-replacement-v1");
    assert_eq!(report["structurallyVerified"], true);
    assert_eq!(report["runtimeVerified"], false);
    assert_eq!(
        report["identity"]["replacementPackageCount"],
        expected_package_count
    );
    let retired_physics_count = report["identity"]["retiredPhysicsAssetReferenceRepairCount"]
        .as_u64()
        .unwrap();
    assert_eq!(
        report["identity"]["payloadMutationCount"],
        retired_physics_count
    );
    assert!(
        report["identity"]["materialImportRepairCount"]
            .as_u64()
            .unwrap()
            > 0
    );
    assert_eq!(
        report["identity"]["skeletonImportRepairCount"],
        expected_package_count
    );
    assert_eq!(
        report["identity"]["sourceExportPayloadsPreserved"],
        retired_physics_count == 0
    );
    assert_eq!(
        report["identity"]["approvedPayloadMigrationRoundtripPreserved"],
        true
    );
    assert_eq!(report["verification"]["roundtripFileSetsPreserved"], true);
    assert_eq!(
        report["verification"]["currentMaterialAndSkeletonImportsMigrated"],
        true
    );
    assert_eq!(
        report["verification"]["serializedMaterialArraysParsed"],
        true
    );
    assert_eq!(
        report["verification"]["materialSlotsResolvedBySerializedName"],
        true
    );
    assert_eq!(
        report["verification"]["retiredPhysicsAssetReferencesNulled"],
        true
    );
    for repair in report["unreal"]["containers"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|container| container["materialImportRepairs"].as_array().unwrap())
    {
        let selected = repair["materialTargets"].as_array().unwrap();
        let slot_names = repair["materialSlotNames"].as_array().unwrap();
        let ignored = repair["ignoredInactiveMaterialDependencies"]
            .as_array()
            .unwrap();
        assert_eq!(slot_names.len(), selected.len());
        let retired = repair["retiredPhysicsAssetImportCount"].as_u64().unwrap();
        assert_eq!(
            repair["retiredPhysicsAssetReferenceOffsets"]
                .as_array()
                .unwrap()
                .len() as u64,
            retired
        );
        assert!(
            repair["staleCreateDependenciesRemoved"].as_u64().unwrap() >= retired,
            "every retired PhysicsAsset import must remove at least one matching dependency"
        );
        assert_eq!(repair["auxiliaryImportCount"], 0);
        assert!(
            !repair["activeDonorMaterialImports"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert!(
            ignored
                .iter()
                .all(|dependency| !selected.contains(dependency))
        );
    }
}

#[test]
#[ignore = "requires an installed game and a local mixed armor expansion fixture"]
fn updates_current_mixed_armor_fixture() {
    let required = |name: &str| {
        std::env::var_os(name)
            .map(PathBuf::from)
            .unwrap_or_else(|| panic!("missing required test environment variable {name}"))
    };
    let expected_package_count = std::env::var("OBR_TEST_MIXED_ARMOR_PACKAGE_COUNT")
        .ok()
        .map(|value| {
            value
                .parse::<usize>()
                .expect("invalid OBR_TEST_MIXED_ARMOR_PACKAGE_COUNT")
        })
        .unwrap_or(1);
    let compatibility_inputs = std::env::var_os("OBR_TEST_BODY_COMPATIBILITY_MOD")
        .map(PathBuf::from)
        .into_iter()
        .collect();
    let mut log = Vec::new();
    let outcome = run_update(
        UpdateRequest {
            adapter: "native-mixed-armor-expansion-v1".to_owned(),
            mod_input: required("OBR_TEST_MIXED_ARMOR_MOD"),
            game_root: required("OBR_TEST_GAME"),
            output_parent: required("OBR_TEST_OUTPUT"),
            dependency_inputs: compatibility_inputs,
            installed_collision_exclusions: Vec::new(),
            persist_settings: false,
        },
        &mut |step, total, message| log.push(format!("[{step}/{total}] {message}")),
    )
    .unwrap_or_else(|error| panic!("mixed armor update failed:\n{error:#}\n{}", log.join("\n")));
    assert!(outcome.output_archive.is_file());
    assert!(outcome.report_path.is_file());
    assert_eq!(outcome.adapter, "native-mixed-armor-expansion-v1");
    assert_eq!(outcome.package_count, expected_package_count);
    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(outcome.report_path).unwrap()).unwrap();
    assert_eq!(report["adapter"], "native-mixed-armor-expansion-v1");
    assert_eq!(report["structurallyVerified"], true);
    assert_eq!(report["runtimeVerified"], false);
    assert_eq!(report["identity"]["packageCount"], expected_package_count);
    assert_eq!(
        report["verification"]["companionContainersBytePreserved"],
        true
    );
    assert_eq!(
        report["verification"]["companionDependencyClosureResolved"],
        true
    );
    assert_eq!(
        report["compatibility"]["sourceGeometryAndSkinWeightsPreserved"],
        true
    );
    assert_eq!(
        report["compatibility"]["externalBodyShapeCompatibilityClaimed"],
        false
    );
    if std::env::var_os("OBR_TEST_BODY_COMPATIBILITY_MOD").is_some() {
        assert_eq!(report["compatibility"]["customSkeletonAutoDetected"], true);
        assert_eq!(
            report["compatibility"]["customSkeletonProfile"]["id"],
            "attached-female-body-profile-v1"
        );
    }
    assert!(
        report["unreal"]["meshDonors"]
            .as_array()
            .is_some_and(|donors| !donors.is_empty())
    );
}

#[test]
#[ignore = "requires an installed game and a local Texture2D replacement fixture"]
fn updates_current_texture_replacement_fixture() {
    let required = |name: &str| {
        std::env::var_os(name)
            .map(PathBuf::from)
            .unwrap_or_else(|| panic!("missing required test environment variable {name}"))
    };
    let mut log = Vec::new();
    let expected_package_count = std::env::var("OBR_TEST_TEXTURE_PACKAGE_COUNT")
        .ok()
        .map(|value| {
            value
                .parse::<usize>()
                .expect("invalid OBR_TEST_TEXTURE_PACKAGE_COUNT")
        })
        .unwrap_or(1);
    let outcome = run_update(
        UpdateRequest {
            adapter: "native-texture-replacement-v1".to_owned(),
            mod_input: required("OBR_TEST_TEXTURE_MOD"),
            game_root: required("OBR_TEST_GAME"),
            output_parent: required("OBR_TEST_OUTPUT"),
            dependency_inputs: Vec::new(),
            installed_collision_exclusions: Vec::new(),
            persist_settings: false,
        },
        &mut |step, total, message| log.push(format!("[{step}/{total}] {message}")),
    )
    .unwrap_or_else(|error| {
        panic!(
            "Texture2D replacement update failed:\n{error:#}\n{}",
            log.join("\n")
        )
    });
    assert!(outcome.output_archive.is_file());
    assert!(outcome.report_path.is_file());
    assert_eq!(outcome.adapter, "native-texture-replacement-v1");
    assert_eq!(outcome.package_count, expected_package_count);
    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(outcome.report_path).unwrap()).unwrap();
    assert_eq!(report["adapter"], "native-texture-replacement-v1");
    assert_eq!(report["structurallyVerified"], true);
    assert_eq!(report["runtimeVerified"], false);
    assert_eq!(
        report["identity"]["texturePackageCount"],
        expected_package_count
    );
    assert_eq!(report["identity"]["textureClassesProven"], true);
    assert_eq!(
        report["identity"]["pixelFormatsMatchedCurrentTargets"],
        true
    );
    assert_eq!(report["identity"]["dependencyFreePackageStores"], true);
    assert_eq!(report["identity"]["rawExportsPreserved"], true);
    assert_eq!(report["identity"]["sidecarsBytePreserved"], true);
    assert_eq!(report["verification"]["roundtripFileSetsPreserved"], true);
    assert_eq!(report["verification"]["uexpAndUbulkBytePreserved"], true);
}
#[test]
#[ignore = "requires an installed game and a local additive StaticMesh fixture"]
fn updates_current_additive_static_mesh_fixture() {
    let required = |name: &str| {
        std::env::var_os(name)
            .map(PathBuf::from)
            .unwrap_or_else(|| panic!("missing required test environment variable {name}"))
    };
    let expected_package_count = std::env::var("OBR_TEST_STATIC_MESH_PACKAGE_COUNT")
        .ok()
        .map(|value| {
            value
                .parse::<usize>()
                .expect("invalid OBR_TEST_STATIC_MESH_PACKAGE_COUNT")
        })
        .unwrap_or(1);
    let mut log = Vec::new();
    let outcome = run_update(
        UpdateRequest {
            adapter: "native-static-mesh-v2".to_owned(),
            mod_input: required("OBR_TEST_STATIC_MESH_MOD"),
            game_root: required("OBR_TEST_GAME"),
            output_parent: required("OBR_TEST_OUTPUT"),
            dependency_inputs: Vec::new(),
            installed_collision_exclusions: Vec::new(),
            persist_settings: false,
        },
        &mut |step, total, message| log.push(format!("[{step}/{total}] {message}")),
    )
    .unwrap_or_else(|error| {
        panic!(
            "additive StaticMesh update failed:\n{error:#}\n{}",
            log.join("\n")
        )
    });
    assert!(outcome.output_archive.is_file());
    assert!(outcome.report_path.is_file());
    assert_eq!(outcome.adapter, "native-static-mesh-v2");
    assert_eq!(outcome.package_count, expected_package_count);
    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(outcome.report_path).unwrap()).unwrap();
    assert_eq!(report["structurallyVerified"], true);
    assert_eq!(report["runtimeVerified"], false);
    assert_eq!(report["verification"]["packagePathsAndIdsPreserved"], true);
    assert_eq!(report["verification"]["packageImportsPreserved"], true);
    assert_eq!(
        report["verification"]["bodySetupCookedPhysicsNormalized"],
        true
    );
    let body_repairs = report["containers"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|container| container["bodySetupRepairs"].as_array().unwrap())
        .collect::<Vec<_>>();
    assert!(!body_repairs.is_empty());
    assert!(
        body_repairs
            .iter()
            .all(|repair| repair["collisionRemoved"] == true)
    );
    assert_eq!(report["verification"]["roundtripFileSetsPreserved"], true);
}

#[test]
#[ignore = "requires an installed game and a local heterogeneous StaticMesh/Texture2D fixture"]
fn updates_current_heterogeneous_replacement_fixture() {
    let required = |name: &str| {
        std::env::var_os(name)
            .map(PathBuf::from)
            .unwrap_or_else(|| panic!("missing required test environment variable {name}"))
    };
    let expected_package_count = std::env::var("OBR_TEST_HETEROGENEOUS_PACKAGE_COUNT")
        .ok()
        .map(|value| {
            value
                .parse::<usize>()
                .expect("invalid OBR_TEST_HETEROGENEOUS_PACKAGE_COUNT")
        })
        .unwrap_or(3);
    let mut log = Vec::new();
    let outcome = run_update(
        UpdateRequest {
            adapter: "native-heterogeneous-static-mesh-texture-v1".to_owned(),
            mod_input: required("OBR_TEST_HETEROGENEOUS_MOD"),
            game_root: required("OBR_TEST_GAME"),
            output_parent: required("OBR_TEST_OUTPUT"),
            dependency_inputs: Vec::new(),
            installed_collision_exclusions: Vec::new(),
            persist_settings: false,
        },
        &mut |step, total, message| log.push(format!("[{step}/{total}] {message}")),
    )
    .unwrap_or_else(|error| {
        panic!(
            "heterogeneous replacement update failed:\n{error:#}\n{}",
            log.join("\n")
        )
    });
    assert!(outcome.output_archive.is_file());
    assert!(outcome.report_path.is_file());
    assert_eq!(
        outcome.adapter,
        "native-heterogeneous-static-mesh-texture-v1"
    );
    assert_eq!(outcome.package_count, expected_package_count);
    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(outcome.report_path).unwrap()).unwrap();
    assert_eq!(report["structurallyVerified"], true);
    assert_eq!(report["runtimeVerified"], false);
    assert_eq!(report["identity"]["packageCount"], expected_package_count);
    assert!(report["identity"]["staticMeshCount"].as_u64().unwrap() > 0);
    assert!(report["identity"]["texture2DCount"].as_u64().unwrap() > 0);
    assert_eq!(report["verification"]["sourceExactCaseExtraction"], true);
    assert_eq!(report["verification"]["packagePathsAndIdsPreserved"], true);
    assert_eq!(report["verification"]["packageImportsPreserved"], true);
    assert_eq!(report["verification"]["roundtripClassesPreserved"], true);
    assert_eq!(
        report["verification"]["payloadsPreservedOutsideAllowedLinkageMetadata"],
        true
    );
}
