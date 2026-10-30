use super::*;

#[test]
fn text_manifest_preserves_namespaces_raw_and_absence() {
    let bytes: Arc<[u8]> = Arc::from(br#"<manifest xmlns:a="http://schemas.android.com/apk/res/android" package="example.test" a:versionCode="7"><uses-permission a:name="p"/><uses-permission a:name="p"/><application><activity a:name=".Main"/><service a:name="S" a:exported="false"/></application></manifest>"#.as_slice());
    let doc = parse_manifest(Arc::clone(&bytes), ManifestLimits::default()).unwrap();
    assert!(Arc::ptr_eq(&bytes, &doc.lease()));
    assert_eq!(doc.summary().permissions.len(), 2);
    assert_eq!(doc.summary().components.len(), 2);
    assert_eq!(doc.summary().components[0].exported, None);
    let attr = doc.nodes()[0]
        .attribute(Some(ANDROID_NS), "versionCode")
        .unwrap();
    assert_eq!(
        &doc.bytes()[attr.source_range.offset..attr.source_range.offset + attr.source_range.length],
        br#"a:versionCode="7""#
    );
}

fn fixture_root() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/manifest")
}

#[test]
fn independent_vectors_cover_full_tree_and_errors() {
    let root = fixture_root();
    let cases: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join("manifest.json")).unwrap()).unwrap();
    let mut passed = 0;
    for case in cases["cases"].as_array().unwrap() {
        let name = case["file"].as_str().unwrap();
        let bytes: Arc<[u8]> = Arc::from(std::fs::read(root.join(name)).unwrap());
        assert_eq!(
            mdd_types::sha256(&bytes),
            case["sha256"].as_str().unwrap(),
            "{name}"
        );
        let result = parse_manifest(Arc::clone(&bytes), ManifestLimits::default());
        if let Some(expected) = case["expected_error"].as_str() {
            let error = result.expect_err(name);
            assert_eq!(
                serde_json::to_value(error.code).unwrap(),
                expected,
                "{name}: {error}"
            );
        } else {
            let doc = result.unwrap_or_else(|error| panic!("{name}: {error}"));
            assert!(Arc::ptr_eq(&bytes, &doc.lease()));
            for node in doc.nodes() {
                assert!(node.source_range.offset + node.source_range.length <= bytes.len());
                for attr in &node.attributes {
                    assert!(attr.source_range.offset + attr.source_range.length <= bytes.len());
                }
            }
            if case["tree"].is_array() {
                let actual: Vec<_> = doc.nodes().iter().map(|node| {
                    let attributes: Vec<_> = node.attributes.iter().map(|attr| {
                        let (data_type, data) = match &attr.value {
                            ManifestValue::Compiled { data_type, raw_data, decoded } => (*data_type,
                                if let TypedData::String { value, .. } = decoded { serde_json::json!(value.text) } else { serde_json::json!(raw_data) }),
                        ManifestValue::Text { value } => return serde_json::json!({"namespace_uri":attr.name.namespace_uri,"name":attr.name.local_name,"text":value.text}),
                        };
                        serde_json::json!({"namespace_uri":attr.name.namespace_uri,"name":attr.name.local_name,
                            "raw":attr.raw_value.as_ref().and_then(|v| v.text.as_ref()),"data_type":data_type,"data":data})
                    }).collect();
                    serde_json::json!({"name":node.name.local_name,"namespace_uri":node.name.namespace_uri,"parent":node.parent,"attributes":attributes})
                }).collect();
                assert_eq!(serde_json::json!(actual), case["tree"], "{name}: full tree");
                if name.ends_with(".axml") {
                    assert_eq!(doc.summary().permissions.len(), 2, "{name}");
                    assert_eq!(doc.summary().declared_permissions.len(), 1, "{name}");
                    assert_eq!(doc.summary().components.len(), 5, "{name}");
                    assert_eq!(doc.summary().components[0].exported, None, "{name}");
                    assert!(matches!(
                        &doc.nodes()[5].attributes[0].value,
                        ManifestValue::Compiled {
                            decoded: TypedData::UnresolvedReference { .. },
                            ..
                        }
                    ));
                }
            }
        }
        passed += 1;
    }
    assert_eq!(passed, 76);
}

#[test]
fn budgets_and_nulls_remain_distinct() {
    let bytes: Arc<[u8]> =
        Arc::from(std::fs::read(fixture_root().join("generated/utf8.axml")).unwrap());
    for field in 0..8 {
        let mut limits = ManifestLimits::default();
        match field {
            0 => limits.max_bytes = 0,
            1 => limits.max_nodes = 0,
            2 => limits.max_depth = 0,
            3 => limits.max_attributes = 0,
            4 => limits.max_strings = 0,
            5 => limits.max_string_units = 0,
            6 => limits.max_events = 0,
            7 => limits.max_work_units = 0,
            _ => unreachable!(),
        }
        assert_eq!(
            parse_manifest(Arc::clone(&bytes), limits).unwrap_err().code,
            ErrorCode::QuotaExceeded,
            "field {field}"
        );
    }
    let doc = parse_manifest(bytes, ManifestLimits::default()).unwrap();
    let app = &doc.nodes()[5];
    assert_eq!(
        app.attribute(None, "nil").unwrap().value,
        ManifestValue::Compiled {
            data_type: 0,
            raw_data: 0,
            decoded: TypedData::Null { empty: false }
        }
    );
    assert_eq!(
        app.attribute(None, "empty").unwrap().value,
        ManifestValue::Compiled {
            data_type: 0,
            raw_data: 1,
            decoded: TypedData::Null { empty: true }
        }
    );
    assert!(app.attribute(None, "absent").is_none());
    assert!(matches!(
        &app.attribute(None, "ratio").unwrap().value,
        ManifestValue::Compiled {
            data_type: 4,
            raw_data: 0x7fc01234,
            decoded: TypedData::FloatBits
        }
    ));
    let doc = parse_manifest(
        Arc::from(
            std::fs::read(fixture_root().join("generated/unpaired-value-utf16.axml")).unwrap(),
        ),
        ManifestLimits::default(),
    )
    .unwrap();
    assert_eq!(doc.strings().last().unwrap().value.utf16, [0xd800]);
    assert_eq!(doc.strings().last().unwrap().value.text, None);
    let doc = parse_manifest(
        Arc::from(std::fs::read(fixture_root().join("generated/ambiguous-prefix.axml")).unwrap()),
        ManifestLimits::default(),
    )
    .unwrap();
    let version = doc.nodes()[0]
        .attribute(Some(ANDROID_NS), "versionCode")
        .unwrap();
    assert_eq!(version.prefix, None);
    assert_eq!(
        version.prefix_provenance,
        PrefixProvenance::AmbiguousNamespaceBindings
    );
    let doc = parse_manifest(
        Arc::from(b"<manifest><uses-sdk/><uses-sdk/></manifest>".as_slice()),
        ManifestLimits::default(),
    )
    .unwrap();
    assert_eq!(doc.summary().uses_sdk_nodes, [1, 2]);
    assert_eq!(
        doc.summary().sdk_attribute_projection,
        "ambiguous_multiple_declarations"
    );
}
