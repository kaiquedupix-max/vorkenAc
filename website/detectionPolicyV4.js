const SEARCH_HOSTS = new Set([
  "google.com",
  "bing.com",
  "duckduckgo.com",
  "search.brave.com",
  "search.yahoo.com",
  "yandex.com",
  "ecosia.org"
]);

const BENIGN_WEB_HOSTS = new Set([
  "vorkenac.guerrafriarust.com.br",
  "iceotimizacoes.store"
]);

function normalizedHost(value) {
  return String(value || "")
    .trim()
    .toLowerCase()
    .replace(/^www\./, "")
    .replace(/\.$/, "");
}

function hostEqualsOrIsSubdomain(host, domain) {
  const normalized = normalizedHost(host);
  const expected = normalizedHost(domain);
  return Boolean(
    normalized &&
    expected &&
    (normalized === expected || normalized.endsWith("." + expected))
  );
}

export function parseHttpUrl(value) {
  try {
    const parsed = new URL(String(value || "").trim());
    if (!["http:", "https:"].includes(parsed.protocol))
      return null;
    return parsed;
  } catch {
    return null;
  }
}

export function isSearchProviderUrl(value) {
  const parsed = parseHttpUrl(value);
  if (!parsed) return false;
  const host = normalizedHost(parsed.hostname);
  return [...SEARCH_HOSTS].some((candidate) =>
    hostEqualsOrIsSubdomain(host, candidate)
  );
}

function isKnownBenignHost(value) {
  const parsed = parseHttpUrl(value);
  if (!parsed) return false;
  return [...BENIGN_WEB_HOSTS].some((candidate) =>
    hostEqualsOrIsSubdomain(parsed.hostname, candidate)
  );
}

function normalizeDomainNeedle(value) {
  const parsed = parseHttpUrl(value);
  if (parsed)
    return normalizedHost(parsed.hostname);

  return normalizedHost(
    String(value || "")
      .replace(/^https?:\/\//i, "")
      .split(/[/?#]/, 1)[0]
  );
}

function candidateUrls(evidence, artifactType) {
  if (artifactType === "browser_history")
    return [evidence?.url];

  if (artifactType === "browser_recovery")
    return [evidence?.recoveredUrl];

  if (artifactType === "browser_download")
    return [evidence?.sourceUrl, evidence?.finalUrl];

  return [
    evidence?.url,
    evidence?.sourceUrl,
    evidence?.finalUrl,
    evidence?.pageUrl,
    evidence?.siteUrl,
    evidence?.referrerUrl,
    evidence?.recoveredUrl,
    ...(Array.isArray(evidence?.urlChain) ? evidence.urlChain : [])
  ];
}

function discordInviteMatches(parsed, invite) {
  const host = normalizedHost(parsed.hostname);
  if (!["discord.gg", "discord.com", "discord.me"].some((candidate) =>
    hostEqualsOrIsSubdomain(host, candidate)
  )) {
    return false;
  }

  const segments = parsed.pathname
    .split("/")
    .filter(Boolean)
    .map((part) => part.toLowerCase());

  const expected = String(invite || "").trim().toLowerCase();
  return Boolean(expected && segments.includes(expected));
}

/**
 * Confirms that a catalog indicator is the actual navigation/download target.
 * Query strings and referrers are deliberately excluded for browser history,
 * preventing a Google result page that merely mentions a domain from becoming
 * a critical direct visit.
 */
export function catalogWebTargetMatch(
  match,
  evidence = {},
  artifactType = ""
) {
  const matchedBy = String(match?.matchedBy || "").toLowerCase();
  const separator = matchedBy.indexOf(":");
  const kind = separator >= 0 ? matchedBy.slice(0, separator) : "";
  const needle = separator >= 0 ? matchedBy.slice(separator + 1) : "";

  if (!["domain", "osint-domain", "osint-url", "discord"].includes(kind))
    return { matched: false, direct: false, candidate: "", kind };

  for (const raw of candidateUrls(evidence, artifactType).filter(Boolean)) {
    const parsed = parseHttpUrl(raw);
    if (!parsed || isSearchProviderUrl(raw) || isKnownBenignHost(raw))
      continue;

    let direct = false;

    if (kind === "discord") {
      direct = discordInviteMatches(parsed, needle);
    } else if (kind === "domain" || kind === "osint-domain") {
      direct = hostEqualsOrIsSubdomain(
        parsed.hostname,
        normalizeDomainNeedle(needle)
      );
    } else {
      const normalizedNeedle = String(needle || "")
        .toLowerCase()
        .replace(/^https?:\/\/(www\.)?/i, "")
        .replace(/[?#].*$/, "")
        .replace(/\/+$/, "");
      const target = (
        normalizedHost(parsed.hostname) + parsed.pathname.toLowerCase()
      ).replace(/\/+$/, "");
      direct = Boolean(
        normalizedNeedle &&
        (target === normalizedNeedle || target.startsWith(normalizedNeedle + "/"))
      );
    }

    if (direct) {
      return {
        matched: true,
        direct: true,
        candidate: parsed.href,
        kind
      };
    }
  }

  return { matched: false, direct: false, candidate: "", kind };
}

export function classifyUnknownExecutableEvidence(evidence = {}) {
  const corroborators = [];

  if (evidence.usb === true) corroborators.push("removable_media");
  if (evidence.deletedOrMissing === true) corroborators.push("deleted_or_missing");
  if (evidence.packedOrHighEntropy === true) corroborators.push("packed_or_high_entropy");
  if (evidence.strongInjection === true) corroborators.push("strong_injection_apis");

  const randomName = Number(evidence.randomLoaderScore || 0) >= 4;
  const enoughIndependentEvidence = corroborators.length >= 2;
  const inSessionTechnicalCorrelation =
    evidence.inSession === true &&
    corroborators.some((item) =>
      ["removable_media", "packed_or_high_entropy", "strong_injection_apis"]
        .includes(item)
    );

  return {
    critical: Boolean(
      evidence.executed === true &&
      evidence.genericInstaller !== true &&
      randomName &&
      (enoughIndependentEvidence || inSessionTechnicalCorrelation)
    ),
    randomName,
    corroborators,
    contextualSignals: evidence.suspiciousPath === true
      ? ["user_writable_path"]
      : []
  };
}

export function classifyExplicitCheatNameEvidence(evidence = {}) {
  const technicalCorroboration = Boolean(
    evidence.usb === true ||
    evidence.deletedOrMissing === true ||
    evidence.packedOrHighEntropy === true ||
    evidence.strongInjection === true
  );

  return {
    critical: Boolean(
      evidence.executed === true &&
      evidence.highRiskName === true &&
      evidence.genericInstaller !== true &&
      evidence.inSession === true &&
      technicalCorroboration
    ),
    review: Boolean(
      evidence.executed === true &&
      evidence.highRiskName === true &&
      evidence.genericInstaller !== true
    )
  };
}
