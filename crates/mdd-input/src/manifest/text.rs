use super::*;
use quick_xml::{Reader, XmlVersion, events::Event};
use std::collections::{BTreeMap, BTreeSet};

const XML_NS: &str = "http://www.w3.org/XML/1998/namespace";
const XMLNS_NS: &str = "http://www.w3.org/2000/xmlns/";
fn name_start(c: char) -> bool {
    matches!(c, 'A'..='Z' | '_' | 'a'..='z' | '\u{c0}'..='\u{d6}' | '\u{d8}'..='\u{f6}' |
        '\u{f8}'..='\u{2ff}' | '\u{370}'..='\u{37d}' | '\u{37f}'..='\u{1fff}' |
        '\u{200c}'..='\u{200d}' | '\u{2070}'..='\u{218f}' | '\u{2c00}'..='\u{2fef}' |
        '\u{3001}'..='\u{d7ff}' | '\u{f900}'..='\u{fdcf}' | '\u{fdf0}'..='\u{fffd}' |
        '\u{10000}'..='\u{effff}')
}
pub(super) fn ncname(name: &str) -> bool {
    let mut chars = name.chars();
    chars.next().is_some_and(name_start) && chars.all(|c| name_start(c) || matches!(c, '-' | '.' | '0'..='9' | '\u{b7}' | '\u{300}'..='\u{36f}' | '\u{203f}'..='\u{2040}'))
}
fn xml_chars(text: &str) -> bool {
    text.chars().all(|c| matches!(c, '\t' | '\n' | '\r' | '\u{20}'..='\u{d7ff}' | '\u{e000}'..='\u{fffd}' | '\u{10000}'..='\u{10ffff}'))
}
fn qname(name: &str) -> MddResult<(Option<&str>, &str)> {
    if let Some((prefix, local)) = name.split_once(':') {
        if ncname(prefix) && ncname(local) {
            return Ok((Some(prefix), local));
        }
    } else if ncname(name) {
        return Ok((None, name));
    }
    Err(invalid("invalid XML qualified name"))
}
pub(super) fn validate_binding(prefix: Option<&str>, uri: &str) -> MddResult<()> {
    if prefix.is_some_and(|p| !ncname(p))
        || !xml_chars(uri)
        || prefix == Some("xmlns")
        || uri == XMLNS_NS
        || (prefix == Some("xml")) != (uri == XML_NS)
        || (prefix.is_some() && uri.is_empty())
    {
        return Err(invalid("invalid XML namespace binding"));
    }
    Ok(())
}
fn expanded(
    name: &str,
    namespaces: &BTreeMap<Option<String>, String>,
    attribute: bool,
) -> MddResult<(ExpandedName, Option<String>)> {
    let (prefix, local) = qname(name)?;
    let uri = if attribute && prefix.is_none() {
        None
    } else {
        match namespaces.get(&prefix.map(str::to_owned)) {
            Some(uri) => Some(uri.clone()),
            None if prefix.is_none() => None,
            None => return Err(invalid("XML namespace prefix is not in scope")),
        }
    };
    Ok((
        ExpandedName {
            namespace_uri: uri,
            local_name: local.to_owned(),
        },
        prefix.map(str::to_owned),
    ))
}
fn resource(text: &str, build: &mut Builder, count: &mut usize) -> MddResult<ResourceText> {
    *count = count
        .checked_add(1)
        .ok_or_else(|| quota("text string count overflow"))?;
    if *count > build.limits.max_strings {
        return Err(quota("text string count exceeds budget"));
    }
    build.units(text.encode_utf16().count())?;
    if !xml_chars(text) {
        return Err(invalid("illegal XML character"));
    }
    Ok(ResourceText::from_str(text))
}
fn text_event(
    text: &str,
    source_range: ByteRange,
    stack: &[(usize, BTreeMap<Option<String>, String>)],
    build: &mut Builder,
    count: &mut usize,
) -> MddResult<()> {
    if stack.is_empty() && !text.chars().all(|c| matches!(c, ' ' | '\n' | '\r' | '\t')) {
        return Err(invalid("non-whitespace XML data outside root"));
    }
    let value = resource(text, build, count)?;
    build.event(ManifestEvent::Text {
        parent: stack.last().map(|s| s.0),
        value,
        typed_value: None,
        source_range,
    })
}

pub(super) fn parse(bytes: &[u8], build: &mut Builder) -> MddResult<()> {
    let input =
        std::str::from_utf8(bytes).map_err(|_| invalid("text Manifest must be strict UTF-8"))?;
    if !xml_chars(input) {
        return Err(invalid("illegal literal XML character"));
    }
    let (content, origin) = input
        .strip_prefix('\u{feff}')
        .map_or((input, 0), |s| (s, 3));
    let mut reader = Reader::from_str(content);
    reader.config_mut().check_comments = true;
    let mut stack: Vec<(usize, BTreeMap<Option<String>, String>)> = Vec::new();
    let mut count = 0usize;
    let mut declaration_seen = false;
    let mut tokens = 0usize;
    loop {
        let begin = reader.buffer_position() as usize + origin;
        let event = reader
            .read_event()
            .map_err(|e| invalid(&format!("invalid XML: {e}")))?;
        let end = reader.buffer_position() as usize + origin;
        let source_range = ByteRange {
            offset: begin,
            length: end - begin,
        };
        if !matches!(event, Event::Eof) {
            if tokens >= build.limits.max_events {
                return Err(quota("XML input event budget exceeded"));
            }
            tokens += 1;
        }
        match event {
            Event::Start(start) | Event::Empty(start) => {
                let empty = bytes.get(end.saturating_sub(2)..end) == Some(b"/>");
                // Reject before copying an inherited namespace environment.
                if stack.len() >= build.limits.max_depth
                    || build.nodes.len() >= build.limits.max_nodes
                {
                    return Err(quota("Manifest node/depth budget exceeded"));
                }
                if let Some((_, inherited)) = stack.last() {
                    // Bound repeated copying of a large inherited namespace map
                    // before allocating the child scope.
                    let units = inherited
                        .iter()
                        .map(|(p, u)| {
                            p.as_deref().map_or(0, |p| p.encode_utf16().count())
                                + u.encode_utf16().count()
                        })
                        .sum();
                    build.units(units)?;
                    build.work(inherited.len())?;
                }
                let mut namespaces = stack.last().map(|s| s.1.clone()).unwrap_or_else(|| {
                    BTreeMap::from([(Some("xml".to_owned()), XML_NS.to_owned())])
                });
                let mut parsed = Vec::new();
                let mut declarations = Vec::new();
                for attribute in start.attributes() {
                    let attribute =
                        attribute.map_err(|e| invalid(&format!("invalid XML attribute: {e}")))?;
                    build.attributes(1)?;
                    let raw_name = attribute.key.as_ref();
                    qname(raw_name)?;
                    build.units(raw_name.encode_utf16().count())?;
                    if attribute.value.contains('<') {
                        return Err(invalid("literal less-than in XML attribute"));
                    }
                    let normalized = attribute
                        .normalized_value(XmlVersion::Implicit1_0)
                        .map_err(|e| invalid(&format!("invalid XML attribute value: {e}")))?;
                    let value = resource(&normalized, build, &mut count)?;
                    let raw = resource(&attribute.value, build, &mut count)?;
                    // Slice-reader events and attributes borrow the original UTF-8
                    // source. Keep the lexical attribute range including quotes.
                    let at = (raw_name.as_ptr() as usize)
                        .checked_sub(input.as_ptr() as usize)
                        .ok_or_else(|| invalid("XML attribute source range is invalid"))?;
                    let last = (attribute.value.as_ptr() as usize)
                        .checked_sub(input.as_ptr() as usize)
                        .and_then(|v| v.checked_add(attribute.value.len() + 1))
                        .ok_or_else(|| invalid("XML attribute source range overflow"))?;
                    if at < begin || last > end || last < at {
                        return Err(invalid("XML attribute source range escapes element"));
                    }
                    let attr_range = ByteRange {
                        offset: at,
                        length: last - at,
                    };
                    if raw_name == "xmlns" || raw_name.starts_with("xmlns:") {
                        let prefix = raw_name.strip_prefix("xmlns:").map(str::to_owned);
                        let uri = normalized.into_owned();
                        validate_binding(prefix.as_deref(), &uri)?;
                        if declarations
                            .iter()
                            .any(|d: &NamespaceDeclaration| d.prefix == prefix)
                        {
                            return Err(invalid("duplicate namespace declaration"));
                        }
                        if uri.is_empty() {
                            namespaces.remove(&prefix);
                        } else {
                            namespaces.insert(prefix.clone(), uri.clone());
                        }
                        declarations.push(NamespaceDeclaration {
                            prefix,
                            uri,
                            source_range: attr_range,
                        });
                    } else {
                        parsed.push((raw_name.to_owned(), raw, value, attr_range));
                    }
                }
                build.units(start.name().as_ref().encode_utf16().count())?;
                let (name, prefix) = expanded(start.name().as_ref(), &namespaces, false)?;
                let mut attributes = Vec::with_capacity(parsed.len());
                let mut seen = BTreeSet::new();
                for (raw_name, raw, value, source_range) in parsed {
                    let (name, prefix) = expanded(&raw_name, &namespaces, true)?;
                    if !seen.insert((name.namespace_uri.clone(), name.local_name.clone())) {
                        return Err(invalid("duplicate expanded XML attribute"));
                    }
                    attributes.push(ManifestAttribute {
                        name,
                        prefix,
                        prefix_provenance: PrefixProvenance::SourceQName,
                        raw_value: Some(raw),
                        value: ManifestValue::Text { value },
                        resource_id: None,
                        source_range,
                    });
                }
                for declaration in &declarations {
                    build.event(ManifestEvent::NamespaceStart {
                        depth: stack.len(),
                        declaration: declaration.clone(),
                    })?;
                }
                let node = ManifestNode {
                    name,
                    prefix,
                    prefix_provenance: PrefixProvenance::SourceQName,
                    parent: stack.last().map(|s| s.0),
                    attributes,
                    namespaces: declarations,
                    source_range: source_range.clone(),
                    line_number: None,
                };
                let id = build.push(node, stack.len() + 1)?;
                if empty {
                    build.event(ManifestEvent::EndElement {
                        node: id,
                        source_range: source_range.clone(),
                    })?;
                    for declaration in build.nodes[id].namespaces.clone().into_iter().rev() {
                        build.event(ManifestEvent::NamespaceEnd {
                            depth: stack.len(),
                            declaration,
                        })?;
                    }
                } else {
                    stack.push((id, namespaces));
                }
            }
            Event::End(end) => {
                let (id, namespaces) = stack
                    .pop()
                    .ok_or_else(|| invalid("XML end without start"))?;
                let (name, _) = expanded(end.name().as_ref(), &namespaces, false)?;
                if build.nodes[id].name != name {
                    return Err(invalid("mismatched XML end element"));
                }
                build.event(ManifestEvent::EndElement {
                    node: id,
                    source_range,
                })?;
                for declaration in build.nodes[id].namespaces.clone().into_iter().rev() {
                    build.event(ManifestEvent::NamespaceEnd {
                        depth: stack.len(),
                        declaration,
                    })?;
                }
            }
            Event::Text(text) => text_event(
                &text.xml10_content(),
                source_range,
                &stack,
                build,
                &mut count,
            )?,
            Event::CData(text) => {
                if stack.is_empty() {
                    return Err(invalid("CDATA outside XML root"));
                }
                text_event(
                    &text.xml10_content(),
                    source_range,
                    &stack,
                    build,
                    &mut count,
                )?;
            }
            Event::GeneralRef(reference) => {
                let value = if let Some(c) = reference
                    .resolve_char_ref()
                    .map_err(|_| invalid("invalid XML character reference"))?
                {
                    c.to_string()
                } else {
                    match reference.as_ref() {
                        "lt" => "<",
                        "gt" => ">",
                        "amp" => "&",
                        "apos" => "'",
                        "quot" => "\"",
                        _ => return Err(invalid("undeclared XML entity")),
                    }
                    .to_owned()
                };
                if stack.is_empty() {
                    return Err(invalid("XML reference outside root"));
                }
                text_event(&value, source_range, &stack, build, &mut count)?;
            }
            Event::DocType(_) => {
                return Err(invalid(
                    "DTD and external entities are forbidden in Manifest",
                ));
            }
            Event::Decl(decl) => {
                if declaration_seen || !build.events.is_empty() || (begin != 0 && begin != 3) {
                    return Err(invalid("misplaced XML declaration"));
                }
                declaration_seen = true;
                if decl
                    .version()
                    .map_err(|_| invalid("bad XML declaration version"))?
                    .as_ref()
                    != "1.0"
                {
                    return Err(MddError::new(
                        ErrorCode::UnsupportedCapability,
                        "manifest.xml",
                        "only XML 1.0 text Manifest is supported",
                    ));
                }
                if let Some(encoding) = decl.encoding()
                    && !encoding
                        .map_err(|_| invalid("bad XML encoding declaration"))?
                        .eq_ignore_ascii_case("utf-8")
                {
                    return Err(invalid("text Manifest encoding declaration is not UTF-8"));
                }
                let mut seen = BTreeSet::new();
                for (ordinal, attr) in
                    quick_xml::events::attributes::Attributes::new(decl.as_ref(), 3).enumerate()
                {
                    let attr = attr.map_err(|_| invalid("bad XML declaration attributes"))?;
                    let name = attr.key.as_ref();
                    if !seen.insert(name.to_owned())
                        || !matches!(name, "version" | "encoding" | "standalone")
                        || (ordinal == 0 && name != "version")
                        || (name == "encoding" && seen.contains("standalone"))
                        || (name == "standalone" && !matches!(attr.value.as_ref(), "yes" | "no"))
                    {
                        return Err(invalid("invalid XML declaration attributes/order"));
                    }
                }
            }
            Event::PI(pi) => {
                if pi.target().eq_ignore_ascii_case("xml") || !ncname(pi.target()) {
                    return Err(invalid("invalid XML processing instruction target"));
                }
            }
            Event::Comment(_) => (),
            Event::Eof => break,
        }
    }
    if !stack.is_empty() {
        return Err(invalid("truncated XML element tree"));
    }
    Ok(())
}
