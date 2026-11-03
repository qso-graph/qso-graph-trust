// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.

//! A reader for the XML TQSL writes, and nothing more: elements, attributes, text, comments and an
//! XML declaration. A DTD, CDATA, processing instructions after the declaration, and any entity but
//! XML's five and character references are refused, so nothing can expand; so is any character XML
//! does not allow. Text and attribute values are normalized as XML says: line ends become `\n`, and
//! in an attribute each literal tab or line end becomes a space.
//!
//! It reads untrusted input that can hold private keys, so it is bounded as it goes, never after:
//! depth, elements and attributes are counted and stopped at their limits, with nothing allocated in
//! proportion to anything else. It reads iteratively, so depth cannot overflow the stack. Text and
//! attribute values are borrowed from the input; decoding one copies it once, into a buffer made at
//! its final size and wiped when dropped.

use std::fmt;

use zeroize::Zeroizing;

/// The deepest nesting read.
pub const MAX_DEPTH: usize = 16;
/// The most elements read.
pub const MAX_ELEMENTS: usize = 2_000_000;
/// The most attributes on one element.
pub const MAX_ATTRIBUTES: usize = 64;

/// Why XML could not be read: where, as a line and column from 1, and what kind of problem.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XmlError {
    pub line: usize,
    pub column: usize,
    pub problem: &'static str,
}

impl fmt::Display for XmlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} at line {}, column {}",
            self.problem, self.line, self.column
        )
    }
}

impl std::error::Error for XmlError {}

/// One element: its name, its attributes, the text directly inside it and its child elements, all
/// borrowing from the input.
#[derive(Debug, Default)]
pub struct Element<'a> {
    pub name: &'a str,
    attributes: Vec<(&'a str, &'a str)>,
    text: Vec<&'a str>,
    pub children: Vec<Element<'a>>,
}

impl<'a> Element<'a> {
    /// An attribute's value, decoded; `None` if it is not there.
    pub fn attribute(&self, name: &str) -> Option<Zeroizing<String>> {
        self.attributes
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, v)| decode([*v].into_iter(), true))
    }

    /// The attributes' names and decoded values, in the order written.
    pub fn attributes(&self) -> impl Iterator<Item = (&'a str, Zeroizing<String>)> + '_ {
        self.attributes
            .iter()
            .map(|(n, v)| (*n, decode([*v].into_iter(), true)))
    }

    /// The text directly inside the element, decoded, comments left out.
    pub fn text(&self) -> Zeroizing<String> {
        decode(self.text.iter().copied(), false)
    }

    /// The child elements with this name.
    pub fn children_named<'s>(&'s self, name: &'s str) -> impl Iterator<Item = &'s Element<'a>> {
        self.children.iter().filter(move |c| c.name == name)
    }
}

/// Decodes text already checked by the reader, as XML 1.0 does (sections 2.11 and 3.3.3): a line end
/// (`\r\n` or a lone `\r`) becomes `\n`, and in an attribute each literal tab or line end becomes a
/// space; then XML's five entities and character references, whose characters are kept as they are
/// (found by Codex review: `HOME<tab>A` and `HOME A` were two names). Decoding only shortens, so the
/// one buffer is made at the input's length.
fn decode<'a>(pieces: impl Iterator<Item = &'a str> + Clone, attribute: bool) -> Zeroizing<String> {
    let len = pieces.clone().map(str::len).sum();
    let mut out = Zeroizing::new(String::with_capacity(len));
    let mut after_cr = false;
    for piece in pieces {
        let mut chars = piece.char_indices();
        while let Some((i, c)) = chars.next() {
            let was_cr = std::mem::replace(&mut after_cr, c == '\r');
            match c {
                '\n' if was_cr => {}
                '\r' | '\n' => out.push(if attribute { ' ' } else { '\n' }),
                '\t' if attribute => out.push(' '),
                '&' => {
                    let rest = &piece[i + 1..];
                    let semi = rest.find(';').unwrap_or(rest.len());
                    out.push(entity(&rest[..semi]).unwrap_or('\u{fffd}'));
                    for _ in 0..semi + 1 {
                        chars.next();
                    }
                }
                c => out.push(c),
            }
        }
    }
    out
}

/// The character an entity names: XML's five, or a character reference (`&#` decimal digits, or
/// `&#x` hexadecimal ones) to a character XML allows.
fn entity(name: &str) -> Option<char> {
    match name {
        "lt" => Some('<'),
        "gt" => Some('>'),
        "amp" => Some('&'),
        "quot" => Some('"'),
        "apos" => Some('\''),
        _ => {
            let number = name.strip_prefix('#')?;
            let (digits, radix) = match number.strip_prefix('x') {
                Some(hex) => (hex, 16),
                None => (number, 10),
            };
            // Digits only: `+` and `-`, which the parser would take, are not XML's.
            if digits.is_empty() || !digits.chars().all(|c| c.is_digit(radix)) {
                return None;
            }
            char::from_u32(u32::from_str_radix(digits, radix).ok()?).filter(|&c| is_xml_char(c))
        }
    }
}

/// Whether XML 1.0 allows a character (section 2.2): tab, line ends, and everything from space up
/// but U+FFFE and U+FFFF (a `char` cannot be a surrogate).
fn is_xml_char(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\r') || (c >= ' ' && c != '\u{fffe}' && c != '\u{ffff}')
}

/// Whether text holds only entities this reader decodes, each ended by `;`.
fn entities_known(text: &str) -> bool {
    let mut rest = text;
    while let Some(amp) = rest.find('&') {
        let Some(semi) = rest[amp..].find(';') else {
            return false;
        };
        if entity(&rest[amp + 1..amp + semi]).is_none() {
            return false;
        }
        rest = &rest[amp + semi + 1..];
    }
    true
}

fn is_name_start(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '_'
}

fn is_name(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ':')
}

struct Reader<'a> {
    input: &'a str,
    at: usize,
}

impl<'a> Reader<'a> {
    fn error(&self, problem: &'static str) -> XmlError {
        let before = &self.input[..self.at];
        let line = before.matches('\n').count() + 1;
        let column = before.rsplit('\n').next().map_or(0, |l| l.chars().count()) + 1;
        XmlError {
            line,
            column,
            problem,
        }
    }

    fn rest(&self) -> &'a str {
        &self.input[self.at..]
    }

    fn skip_space(&mut self) {
        let rest = self.rest();
        self.at += rest.len() - rest.trim_start_matches([' ', '\t', '\r', '\n']).len();
    }

    /// Past `end`, which must come.
    fn past(&mut self, end: &str, problem: &'static str) -> Result<&'a str, XmlError> {
        let found = self.rest().find(end).ok_or_else(|| self.error(problem))?;
        let skipped = &self.rest()[..found];
        self.at += found + end.len();
        Ok(skipped)
    }

    fn name(&mut self) -> Result<&'a str, XmlError> {
        let rest = self.rest();
        if !rest.starts_with(is_name_start) {
            return Err(self.error("a name was expected"));
        }
        let len = rest.find(|c: char| !is_name(c)).unwrap_or(rest.len());
        self.at += len;
        Ok(&rest[..len])
    }
}

/// The root element of an XML document.
pub fn parse(input: &str) -> Result<Element<'_>, XmlError> {
    let mut r = Reader { input, at: 0 };
    // Every character first: XML forbids control characters but tab and line ends (found by Codex
    // review: NUL and U+0001 were read).
    if let Some((at, _)) = input.char_indices().find(|(_, c)| !is_xml_char(*c)) {
        r.at = at;
        return Err(r.error("a character XML does not allow"));
    }
    if r.rest().starts_with('\u{feff}') {
        r.at += '\u{feff}'.len_utf8();
    }
    if r.rest().starts_with("<?xml") {
        r.past("?>", "the XML declaration does not end")?;
    }
    // Open elements, innermost last; the root is taken out when it closes.
    let mut open: Vec<Element> = Vec::new();
    let mut root: Option<Element> = None;
    let mut elements = 0usize;
    loop {
        // Text up to the next tag: kept only inside an element.
        let text_end = r.rest().find('<').unwrap_or(r.rest().len());
        let text = &r.rest()[..text_end];
        if !text.is_empty() {
            match open.last_mut() {
                Some(parent) => {
                    if !entities_known(text) {
                        return Err(r.error("an unknown entity or a bare &"));
                    }
                    parent.text.push(text);
                }
                None if text.trim_matches([' ', '\t', '\r', '\n']).is_empty() => {}
                None => return Err(r.error("text outside the root element")),
            }
            r.at += text_end;
        }
        if r.at == input.len() {
            break;
        }
        let rest = r.rest();
        if rest.starts_with("<!--") {
            r.at += 4;
            r.past("-->", "a comment does not end")?;
        } else if rest.starts_with("<!") {
            return Err(r.error("a DTD or CDATA, which TQSL does not write"));
        } else if rest.starts_with("<?") {
            return Err(r.error("a processing instruction"));
        } else if rest.starts_with("</") {
            r.at += 2;
            let name = r.name()?;
            r.skip_space();
            if !r.rest().starts_with('>') {
                return Err(r.error("an end tag does not end"));
            }
            r.at += 1;
            let element = open
                .pop()
                .ok_or_else(|| r.error("an end tag with no start"))?;
            if element.name != name {
                return Err(r.error("an end tag for another element"));
            }
            match open.last_mut() {
                Some(parent) => parent.children.push(element),
                None => root = Some(element),
            }
        } else {
            r.at += 1;
            if root.is_some() {
                return Err(r.error("a second root element"));
            }
            elements += 1;
            if elements > MAX_ELEMENTS {
                return Err(r.error("too many elements"));
            }
            if open.len() == MAX_DEPTH {
                return Err(r.error("elements nested too deep"));
            }
            let mut element = Element {
                name: r.name()?,
                ..Element::default()
            };
            loop {
                let before = r.at;
                r.skip_space();
                let rest = r.rest();
                if rest.starts_with("/>") || rest.starts_with('>') {
                    break;
                }
                if r.at == before {
                    return Err(r.error("attributes must be separated by space"));
                }
                if element.attributes.len() == MAX_ATTRIBUTES {
                    return Err(r.error("too many attributes"));
                }
                let name = r.name()?;
                r.skip_space();
                if !r.rest().starts_with('=') {
                    return Err(r.error("an attribute with no value"));
                }
                r.at += 1;
                r.skip_space();
                let quote = match r.rest().chars().next() {
                    Some(q @ ('"' | '\'')) => q,
                    _ => return Err(r.error("an attribute value must be quoted")),
                };
                r.at += 1;
                let value = r.past(
                    if quote == '"' { "\"" } else { "'" },
                    "an attribute value does not end",
                )?;
                if value.contains('<') || !entities_known(value) {
                    return Err(r.error("an attribute value with < or an unknown entity"));
                }
                if element.attributes.iter().any(|(n, _)| *n == name) {
                    return Err(r.error("an attribute given twice"));
                }
                element.attributes.push((name, value));
            }
            if r.rest().starts_with("/>") {
                r.at += 2;
                match open.last_mut() {
                    Some(parent) => parent.children.push(element),
                    None => root = Some(element),
                }
            } else {
                r.at += 1;
                open.push(element);
            }
        }
    }
    if !open.is_empty() {
        return Err(r.error("an element does not end"));
    }
    root.ok_or_else(|| r.error("no root element"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn what_tqsl_writes_is_read() {
        let doc = parse(
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<A>\n<!-- a note -->\n<B x=\"1\" y='a &amp; b'>te<!-- c -->xt &lt;&#65;&#x42;</B>\n<C/>\n</A>\n",
        )
        .expect("parses");
        assert_eq!(doc.name, "A");
        assert_eq!(doc.children.len(), 2);
        let b = &doc.children[0];
        assert_eq!(b.attribute("x").as_deref().map(String::as_str), Some("1"));
        assert_eq!(
            b.attribute("y").as_deref().map(String::as_str),
            Some("a & b")
        );
        assert_eq!(b.text().as_str(), "text <AB");
        assert_eq!(doc.children_named("C").count(), 1);
    }

    #[test]
    fn what_could_expand_or_hide_is_refused() {
        for (bad, problem) in [
            (
                "<!DOCTYPE a [<!ENTITY x \"y\">]><a>&x;</a>",
                "a DTD or CDATA, which TQSL does not write",
            ),
            (
                "<a><![CDATA[x]]></a>",
                "a DTD or CDATA, which TQSL does not write",
            ),
            ("<a>&x;</a>", "an unknown entity or a bare &"),
            ("<a>a & b</a>", "an unknown entity or a bare &"),
            (
                "<a b=\"&x;\"/>",
                "an attribute value with < or an unknown entity",
            ),
            ("<a><?pi x?></a>", "a processing instruction"),
            ("<a b=\"1\" b=\"2\"/>", "an attribute given twice"),
            ("<a b=1/>", "an attribute value must be quoted"),
            ("<a></b>", "an end tag for another element"),
            ("<a>", "an element does not end"),
            ("<a/><b/>", "a second root element"),
            ("text<a/>", "text outside the root element"),
            ("<a><!-- open", "a comment does not end"),
            ("", "no root element"),
        ] {
            assert_eq!(
                parse(bad).map(|_| ()).map_err(|e| e.problem),
                Err(problem),
                "{bad}"
            );
        }
    }

    #[test]
    fn limits_are_kept_while_reading() {
        let deep = "<a>".repeat(MAX_DEPTH + 1);
        assert_eq!(
            parse(&deep).err().map(|e| e.problem),
            Some("elements nested too deep")
        );
        let attrs: String = (0..=MAX_ATTRIBUTES)
            .map(|i| format!(" a{i}=\"\""))
            .collect();
        assert_eq!(
            parse(&format!("<a{attrs}/>")).err().map(|e| e.problem),
            Some("too many attributes")
        );
        // Codex review: 128 MiB of < inside a comment made another parser reserve gigabytes; here
        // a comment is skipped, nothing reserved.
        let comment = format!("<a><!--{}--></a>", "<".repeat(1 << 20));
        assert!(parse(&comment).is_ok());
        let many = format!("<a>{}</a>", "<b/>".repeat(MAX_ELEMENTS));
        assert_eq!(
            parse(&many).err().map(|e| e.problem),
            Some("too many elements")
        );
    }

    #[test]
    fn values_are_normalized_as_xml_says() {
        let doc = parse("<a n=\"HOME\tA\" m=\"x\r\ny\" r=\"&#9;\">one\r\ntwo\rthree</a>")
            .expect("parses");
        assert_eq!(
            doc.attribute("n").as_deref().map(String::as_str),
            Some("HOME A")
        );
        assert_eq!(
            doc.attribute("m").as_deref().map(String::as_str),
            Some("x y")
        );
        // A tab written as a reference is kept.
        assert_eq!(
            doc.attribute("r").as_deref().map(String::as_str),
            Some("\t")
        );
        assert_eq!(doc.text().as_str(), "one\ntwo\nthree");
    }

    #[test]
    fn characters_xml_forbids_are_refused() {
        for bad in [
            "<a>\u{1}</a>",
            "<a b=\"\0\"/>",
            "<a>&#1;</a>",
            "<a>&#0;</a>",
            "<a>&#+65;</a>",
            "<a>&#x;</a>",
        ] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
        assert!(parse("<a>&#65;&#x42;\u{7f}</a>").is_ok());
    }

    #[test]
    fn errors_say_where() {
        let e = parse("<a>\n  <b>&x;</b>\n</a>").expect_err("refused");
        assert_eq!((e.line, e.column), (2, 6));
    }

    #[test]
    fn decoded_text_is_wiped_and_made_at_its_size() {
        fn wiped<T: zeroize::ZeroizeOnDrop>(_: &T) {}
        let doc = parse("<a>abc&amp;def</a>").expect("parses");
        let text = doc.text();
        wiped(&text);
        assert!(text.capacity() >= text.len() && text.capacity() <= "abc&amp;def".len());
    }
}
