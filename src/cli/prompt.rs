use std::io::{self, BufRead, Write};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayChoice {
    Skip,
    Details,
    Allow,
    Abort,
}

pub fn parse_choice(input: &str) -> Option<GatewayChoice> {
    match input.trim().to_ascii_lowercase().as_str() {
        "" | "s" => Some(GatewayChoice::Skip),
        "d" => Some(GatewayChoice::Details),
        "a" => Some(GatewayChoice::Allow),
        "q" => Some(GatewayChoice::Abort),
        _ => None,
    }
}

pub fn select_package<W: Write, R: BufRead>(
    writer: &mut W,
    reader: &mut R,
    packages: &[String],
) -> io::Result<Option<usize>> {
    writeln!(writer, "  Select package to allow once:")?;
    for (index, package) in packages.iter().enumerate() {
        writeln!(writer, "  [{}] {}", index + 1, package)?;
    }
    write!(writer, "  Package number: ")?;
    writer.flush()?;

    let mut input = String::new();
    if reader.read_line(&mut input)? == 0 {
        return Ok(None);
    }
    let Ok(number) = input.trim().parse::<usize>() else {
        return Ok(None);
    };
    Ok(number
        .checked_sub(1)
        .filter(|index| *index < packages.len()))
}

pub fn confirm<W: Write, R: BufRead>(writer: &mut W, reader: &mut R) -> io::Result<bool> {
    write!(writer, "  Allow selected package once? [y/N]: ")?;
    writer.flush()?;
    let mut input = String::new();
    if reader.read_line(&mut input)? == 0 {
        return Ok(false);
    }
    Ok(matches!(
        input.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

pub fn ask<W: Write, R: BufRead>(
    writer: &mut W,
    reader: &mut R,
) -> io::Result<Option<GatewayChoice>> {
    writeln!(writer, "\n  [!] Blocked package(s) found")?;
    writeln!(
        writer,
        "  [s] Skip blocked package(s) and continue (default)"
    )?;
    writeln!(writer, "  [d] Show audit details")?;
    writeln!(writer, "  [a] Allow package once")?;
    writeln!(writer, "  [q] Abort upgrade")?;
    write!(writer, "  Choice: ")?;
    writer.flush()?;

    let mut input = String::new();
    if reader.read_line(&mut input)? == 0 {
        return Ok(None);
    }
    Ok(parse_choice(&input))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_choices_correctly() {
        assert_eq!(parse_choice(""), Some(GatewayChoice::Skip));
        assert_eq!(parse_choice("s"), Some(GatewayChoice::Skip));
        assert_eq!(parse_choice("S"), Some(GatewayChoice::Skip));
        assert_eq!(parse_choice("d"), Some(GatewayChoice::Details));
        assert_eq!(parse_choice("a"), Some(GatewayChoice::Allow));
        assert_eq!(parse_choice("q"), Some(GatewayChoice::Abort));
        assert_eq!(parse_choice("unknown"), None);
    }

    #[test]
    fn select_package_indexes_correctly() {
        let pkgs = vec!["pkg-a".into(), "pkg-b".into()];
        let mut out = Vec::new();
        let mut input = std::io::Cursor::new(b"2\n");
        let selected = select_package(&mut out, &mut input, &pkgs).unwrap();
        assert_eq!(selected, Some(1));

        let mut out = Vec::new();
        let mut input = std::io::Cursor::new(b"0\n");
        assert_eq!(select_package(&mut out, &mut input, &pkgs).unwrap(), None);

        let mut out = Vec::new();
        let mut input = std::io::Cursor::new(b"3\n");
        assert_eq!(select_package(&mut out, &mut input, &pkgs).unwrap(), None);
    }

    #[test]
    fn confirmation_handles_yes_and_no() {
        let mut out = Vec::new();
        let mut input = std::io::Cursor::new(b"y\n");
        assert!(confirm(&mut out, &mut input).unwrap());

        let mut out = Vec::new();
        let mut input = std::io::Cursor::new(b"n\n");
        assert!(!confirm(&mut out, &mut input).unwrap());
    }
}
