use std::io::{self, BufRead, Write};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayChoice {
    Skip,
    Details,
    ExplainAi,
    Allow,
    Abort,
}

pub fn parse_choice(input: &str) -> Option<GatewayChoice> {
    match input.trim().to_ascii_lowercase().as_str() {
        "" | "s" => Some(GatewayChoice::Skip),
        "d" => Some(GatewayChoice::Details),
        "e" => Some(GatewayChoice::ExplainAi),
        "a" => Some(GatewayChoice::Allow),
        "q" => Some(GatewayChoice::Abort),
        _ => None,
    }
}

pub fn parse_package_selection(input: &str, total: usize) -> Vec<usize> {
    let clean = input.trim();
    if clean.is_empty() || total == 0 {
        return Vec::new();
    }

    if clean.eq_ignore_ascii_case("all") || clean.eq_ignore_ascii_case("a") || clean == "*" {
        return (0..total).collect();
    }

    let mut selected = std::collections::BTreeSet::new();
    let parts = clean.split([',', ' ']).filter(|p| !p.is_empty());

    for part in parts {
        if let Some((start_s, end_s)) = part.split_once('-') {
            if let (Ok(start), Ok(end)) = (
                start_s.trim().parse::<usize>(),
                end_s.trim().parse::<usize>(),
            ) {
                let (lo, hi) = if start <= end {
                    (start, end)
                } else {
                    (end, start)
                };
                for num in lo..=hi {
                    if num >= 1 && num <= total {
                        selected.insert(num - 1);
                    }
                }
            }
        } else if let Ok(num) = part.parse::<usize>()
            && num >= 1
            && num <= total
        {
            selected.insert(num - 1);
        }
    }

    selected.into_iter().collect()
}

pub fn select_packages<W: Write, R: BufRead>(
    writer: &mut W,
    reader: &mut R,
    packages: &[String],
) -> io::Result<Vec<usize>> {
    writeln!(writer, "  Select package(s) to allow once:")?;
    for (index, package) in packages.iter().enumerate() {
        writeln!(writer, "  [{}] {}", index + 1, package)?;
    }
    writeln!(writer, "  [a] All packages (or range like 1-4, or 1,3,5)")?;
    write!(writer, "  Selection: ")?;
    writer.flush()?;

    let mut input = String::new();
    if reader.read_line(&mut input)? == 0 {
        return Ok(Vec::new());
    }
    Ok(parse_package_selection(&input, packages.len()))
}

pub fn confirm<W: Write, R: BufRead>(
    writer: &mut W,
    reader: &mut R,
    prompt_text: &str,
) -> io::Result<bool> {
    write!(writer, "  {prompt_text} [y/N]: ")?;
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
    writeln!(writer, "  [e] Explain with AI (triage assistance)")?;
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
        assert_eq!(parse_choice("D"), Some(GatewayChoice::Details));
        assert_eq!(parse_choice("e"), Some(GatewayChoice::ExplainAi));
        assert_eq!(parse_choice("E"), Some(GatewayChoice::ExplainAi));
        assert_eq!(parse_choice("a"), Some(GatewayChoice::Allow));
        assert_eq!(parse_choice("q"), Some(GatewayChoice::Abort));
        assert_eq!(parse_choice("unknown"), None);
    }

    #[test]
    fn parses_package_selection_inputs() {
        assert_eq!(parse_package_selection("1", 5), vec![0]);
        assert_eq!(parse_package_selection("1,3,5", 5), vec![0, 2, 4]);
        assert_eq!(parse_package_selection("1 3 5", 5), vec![0, 2, 4]);
        assert_eq!(parse_package_selection("1-3", 5), vec![0, 1, 2]);
        assert_eq!(parse_package_selection("1-9", 5), vec![0, 1, 2, 3, 4]);
        assert_eq!(parse_package_selection("all", 5), vec![0, 1, 2, 3, 4]);
        assert_eq!(parse_package_selection("a", 5), vec![0, 1, 2, 3, 4]);
        assert_eq!(parse_package_selection("*", 5), vec![0, 1, 2, 3, 4]);
        assert_eq!(parse_package_selection("1-2, 4", 5), vec![0, 1, 3]);
        assert_eq!(parse_package_selection("99", 5), Vec::<usize>::new());
    }

    #[test]
    fn confirmation_handles_yes_and_no() {
        let mut out = Vec::new();
        let mut input = std::io::Cursor::new(b"y\n");
        assert!(confirm(&mut out, &mut input, "Allow?").unwrap());

        let mut out = Vec::new();
        let mut input = std::io::Cursor::new(b"n\n");
        assert!(!confirm(&mut out, &mut input, "Allow?").unwrap());
    }
}
