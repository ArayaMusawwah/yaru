use serde::Deserialize;

#[derive(Debug, Clone)]
pub struct AurPackage {
    pub name: String,
    pub version: String,
    pub maintainer: Option<String>,
    pub url: Option<String>,
    pub url_path: Option<String>,
    pub depends: Vec<String>,
    pub makedepends: Vec<String>,
    pub checkdepends: Vec<String>,
    pub out_of_date: Option<i64>,
    pub num_votes: u32,
    pub popularity: f64,
    pub first_submitted: i64,
    pub last_modified: i64,
}

#[derive(Debug, thiserror::Error)]
pub enum AurError {
    #[error("network error: {0}")]
    Network(String),
    #[error("AUR RPC returned unexpected payload")]
    Malformed,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct WireAurPackage {
    name: String,
    version: String,
    maintainer: Option<String>,
    #[serde(rename = "URL")]
    url: Option<String>,
    #[serde(rename = "URLPath")]
    url_path: Option<String>,
    #[serde(default)]
    depends: Vec<String>,
    #[serde(default, rename = "MakeDepends")]
    makedepends: Vec<String>,
    #[serde(default, rename = "CheckDepends")]
    checkdepends: Vec<String>,
    out_of_date: Option<i64>,
    num_votes: u32,
    popularity: f64,
    first_submitted: i64,
    last_modified: i64,
}

#[derive(Deserialize)]
struct WireResponse {
    resultcount: u32,
    results: Vec<WireAurPackage>,
}

impl From<WireAurPackage> for AurPackage {
    fn from(w: WireAurPackage) -> Self {
        Self {
            name: w.name,
            version: w.version,
            maintainer: w.maintainer,
            url: w.url,
            url_path: w.url_path,
            depends: w.depends,
            makedepends: w.makedepends,
            checkdepends: w.checkdepends,
            out_of_date: w.out_of_date,
            num_votes: w.num_votes,
            popularity: w.popularity,
            first_submitted: w.first_submitted,
            last_modified: w.last_modified,
        }
    }
}

pub fn parse_info_response(bytes: &[u8]) -> Result<Option<AurPackage>, AurError> {
    let resp: WireResponse = serde_json::from_slice(bytes).map_err(|_| AurError::Malformed)?;
    if resp.resultcount == 0 {
        return Ok(None);
    }
    resp.results
        .into_iter()
        .next()
        .map(|w| Ok(Some(AurPackage::from(w))))
        .unwrap_or(Err(AurError::Malformed))
}

fn parse_batch_response(bytes: &[u8]) -> Result<Vec<AurPackage>, AurError> {
    let resp: WireResponse = serde_json::from_slice(bytes).map_err(|_| AurError::Malformed)?;
    Ok(resp.results.into_iter().map(AurPackage::from).collect())
}

pub struct AurClient {
    client: reqwest::Client,
    base_url: String,
}

impl AurClient {
    pub fn new() -> Self {
        Self::with_base_url("https://aur.archlinux.org")
    }

    pub fn with_base_url(base: impl Into<String>) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .expect("failed to build HTTP client");
        Self {
            client,
            base_url: base.into(),
        }
    }

    pub async fn info(&self, package: &str) -> Result<Option<AurPackage>, AurError> {
        let url = format!("{}/rpc/v5/info", self.base_url);
        let bytes = self
            .client
            .get(&url)
            .query(&[("arg[]", package)])
            .send()
            .await
            .map_err(|e| AurError::Network(e.to_string()))?
            .bytes()
            .await
            .map_err(|e| AurError::Network(e.to_string()))?;
        parse_info_response(&bytes)
    }

    pub async fn info_batch(&self, packages: &[String]) -> Result<Vec<AurPackage>, AurError> {
        let url = format!("{}/rpc/v5/info", self.base_url);
        let params: Vec<(&str, &str)> = packages.iter().map(|p| ("arg[]", p.as_str())).collect();
        let bytes = self
            .client
            .get(&url)
            .query(&params)
            .send()
            .await
            .map_err(|e| AurError::Network(e.to_string()))?
            .bytes()
            .await
            .map_err(|e| AurError::Network(e.to_string()))?;
        parse_batch_response(&bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOGLE_CHROME_JSON: &[u8] = br#"{"resultcount":1,"results":[{"Depends":["alsa-lib","gtk3"],"Description":"The popular web browser by Google (Stable Channel)","FirstSubmitted":1274819156,"ID":2234866,"Keywords":["chromium"],"LastModified":1789037980,"License":["custom:chrome"],"Maintainer":"gromit","Name":"google-chrome","NumVotes":2371,"OutOfDate":null,"PackageBase":"google-chrome","PackageBaseID":37469,"Popularity":12.714208,"URL":"https://www.google.com/chrome","URLPath":"/cgit/aur.git/snapshot/google-chrome.tar.gz","Version":"153.0.8010.36-1"}],"type":"multiinfo","version":5}"#;

    const EMPTY_JSON: &[u8] = br#"{"resultcount":0,"results":[],"type":"multiinfo","version":5}"#;

    #[test]
    fn parse_google_chrome_package() {
        let pkg = parse_info_response(GOOGLE_CHROME_JSON)
            .expect("should parse")
            .expect("should have result");
        assert_eq!(pkg.name, "google-chrome");
        assert_eq!(pkg.version, "153.0.8010.36-1");
        assert_eq!(pkg.maintainer.as_deref(), Some("gromit"));
        assert_eq!(pkg.url.as_deref(), Some("https://www.google.com/chrome"));
        assert_eq!(
            pkg.url_path.as_deref(),
            Some("/cgit/aur.git/snapshot/google-chrome.tar.gz")
        );
        assert_eq!(pkg.depends, vec!["alsa-lib", "gtk3"]);
        assert!(pkg.makedepends.is_empty());
        assert!(pkg.checkdepends.is_empty());
        assert!(pkg.out_of_date.is_none());
        assert_eq!(pkg.num_votes, 2371);
        assert!((pkg.popularity - 12.714208).abs() < 0.001);
        assert_eq!(pkg.first_submitted, 1274819156);
        assert_eq!(pkg.last_modified, 1789037980);
    }

    #[test]
    fn parse_empty_resultcount_returns_none() {
        let result = parse_info_response(EMPTY_JSON).expect("should parse");
        assert!(result.is_none());
    }

    #[test]
    fn parse_garbage_returns_malformed() {
        let result = parse_info_response(b"not json");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, AurError::Malformed));
    }

    #[test]
    fn parse_batch_empty() {
        let result = parse_batch_response(EMPTY_JSON).expect("should parse");
        assert!(result.is_empty());
    }

    #[test]
    fn parse_batch_one() {
        let result = parse_batch_response(GOOGLE_CHROME_JSON).expect("should parse");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].name, "google-chrome");
    }
}
