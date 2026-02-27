type ThreatRecord = {
  id: string;
  image: string | null;
  threatActor: string | null;
  timestamp: string | null;
  origin: string | null;
  sector: string | null;
  title: string | null;
  sourceUrl: string | null;
};

type CliOptions = {
  url?: string;
  file?: string;
  out?: string;
};

function parseArgs(argv: string[]): CliOptions {
  const options: CliOptions = {};

  for (let index = 0; index < argv.length; index += 1) {
    const value = argv[index];

    if (value === "--url") {
      options.url = argv[index + 1];
      index += 1;
      continue;
    }

    if (value === "--file") {
      options.file = argv[index + 1];
      index += 1;
      continue;
    }

    if (value === "--out") {
      options.out = argv[index + 1];
      index += 1;
    }
  }

  return options;
}

function normalizeText(value: string | null | undefined): string | null {
  if (!value) {
    return null;
  }

  const normalized = value.replace(/\s+/g, " ").trim();
  return normalized.length > 0 ? normalized : null;
}

function decodeEntities(value: string): string {
  return value
    .replace(/&#(x?[0-9a-fA-F]+);/g, (_, code: string) => {
      const isHex = code.toLowerCase().startsWith("x");
      const raw = isHex ? code.slice(1) : code;
      const num = Number.parseInt(raw, isHex ? 16 : 10);
      return Number.isFinite(num) ? String.fromCodePoint(num) : _;
    })
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&nbsp;/g, " ");
}

function stripTags(value: string): string {
  return decodeEntities(value.replace(/<[^>]*>/g, " "));
}

function extractFirst(block: string, expression: RegExp): string | null {
  const match = expression.exec(block);
  if (!match || !match[1]) {
    return null;
  }

  return normalizeText(stripTags(match[1]));
}

function extractRawFirst(block: string, expression: RegExp): string | null {
  const match = expression.exec(block);
  if (!match || !match[1]) {
    return null;
  }

  return match[1];
}

function extractDetailValue(block: string, label: string): string | null {
  const escapedLabel = label.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const pattern = new RegExp(
    `<div[^>]*class="[^"]*detail-label[^"]*"[^>]*>\\s*${escapedLabel}\\s*<\\/div>\\s*<div[^>]*class="[^"]*detail-val[^"]*"[^>]*>([\\s\\S]*?)<\\/div>`,
    "i",
  );

  return extractFirst(block, pattern);
}

function isTelegramUrl(url: string): boolean {
  return /(^|\/\/)(t\.me|telegram\.me|telegram\.org)\//i.test(url);
}

function isForumLikeUrl(url: string): boolean {
  const normalized = url.toLowerCase();

  if (/(breachforums|darkforums|leakbase|raidforums|xss|exploit)/i.test(normalized)) {
    return true;
  }

  return /(\/thread-|\/thread\/|\/topic\/|\/forums?\/)/i.test(normalized);
}

function rankSourceUrl(url: string): number {
  if (isForumLikeUrl(url)) {
    return 3;
  }

  if (isTelegramUrl(url)) {
    return 1;
  }

  return 2;
}

function extractPreferredSourceUrl(block: string): string | null {
  const candidates: { href: string; text: string }[] = [];

  for (const match of block.matchAll(/<a[^>]*href="([^"]+)"[^>]*>([\s\S]*?)<\/a>/gi)) {
    const href = normalizeText(decodeEntities(match[1] ?? ""));
    const text = normalizeText(stripTags(match[2] ?? "")) ?? "";

    if (!href) {
      continue;
    }

    candidates.push({ href, text });
  }

  if (candidates.length === 0) {
    return null;
  }

  const sourceCandidates = candidates.filter((candidate) => /source/i.test(candidate.text));
  const pool = sourceCandidates.length > 0 ? sourceCandidates : candidates;

  pool.sort((left, right) => rankSourceUrl(right.href) - rankSourceUrl(left.href));
  return pool[0]?.href ?? null;
}

function parseModal(id: string, block: string): ThreatRecord {
  const hasDetailLayout = /class="[^"]*detail-label[^"]*"/i.test(block);

  const title = hasDetailLayout
    ? extractFirst(block, /<h5[^>]*class="[^"]*text-white[^"]*"[^>]*>([\s\S]*?)<\/h5>/i) ??
      extractFirst(block, /<h6[^>]*class="[^"]*card-title-tech[^"]*"[^>]*>([\s\S]*?)<\/h6>/i)
    : extractFirst(block, /<h6[^>]*class="[^"]*card-title-tech[^"]*"[^>]*>([\s\S]*?)<\/h6>/i) ??
      extractFirst(block, /<h5[^>]*class="[^"]*text-white[^"]*"[^>]*>([\s\S]*?)<\/h5>/i);

  let image: string | null = null;
  for (const imageMatch of block.matchAll(/<img[^>]*src="([^"]+)"[^>]*>/gi)) {
    const fullTag = imageMatch[0] ?? "";
    const source = normalizeText(decodeEntities(imageMatch[1] ?? ""));
    if (!source) {
      continue;
    }

    if (/flag-img/i.test(fullTag) || /flagcdn\.com/i.test(source)) {
      continue;
    }

    image = source;
    break;
  }

  const threatActor = hasDetailLayout
    ? extractDetailValue(block, "THREAT ACTOR") ??
      extractFirst(block, /<strong>\s*ACTOR:\s*<\/strong>\s*([\s\S]*?)<\/div>/i)
    : extractFirst(block, /<strong>\s*ACTOR:\s*<\/strong>\s*([\s\S]*?)<\/div>/i) ??
      extractDetailValue(block, "THREAT ACTOR");

  const timestamp = hasDetailLayout
    ? extractDetailValue(block, "TIMESTAMP") ??
      extractFirst(block, /<strong>\s*DATE:\s*<\/strong>\s*([\s\S]*?)<\/div>/i)
    : extractFirst(block, /<strong>\s*DATE:\s*<\/strong>\s*([\s\S]*?)<\/div>/i) ??
      extractDetailValue(block, "TIMESTAMP");

  const origin = hasDetailLayout
    ? extractDetailValue(block, "ORIGIN") ??
      extractFirst(block, /<strong>\s*TARGET:\s*<\/strong>\s*([\s\S]*?)<\/div>/i)
    : extractFirst(block, /<strong>\s*TARGET:\s*<\/strong>\s*([\s\S]*?)<\/div>/i) ??
      extractDetailValue(block, "ORIGIN");

  const sectorFromLegacy = extractFirst(
    block,
    /<div[^>]*class="[^"]*sector-badge[^"]*"[^>]*>([\s\S]*?)<\/div>/i,
  )?.replace(/^>\s*/, "") ?? null;

  const sectorFromDetail = extractFirst(
    block,
    /<span[^>]*class="[^"]*detail-label[^"]*"[^>]*>\s*SECTOR:\s*<\/span>\s*<span[^>]*class="[^"]*tech-badge[^"]*"[^>]*>([\s\S]*?)<\/span>/i,
  );

  const sector = hasDetailLayout
    ? sectorFromDetail ?? sectorFromLegacy
    : sectorFromLegacy ?? sectorFromDetail;

  const sourceUrl = extractPreferredSourceUrl(block);

  return {
    id,
    image,
    threatActor,
    timestamp,
    origin,
    sector,
    title,
    sourceUrl,
  };
}

export function parseThreatReports(html: string): ThreatRecord[] {
  const records: ThreatRecord[] = [];
  const modalPattern =
    /<div\s+[^>]*id="modal-content-(\d+)"[^>]*>([\s\S]*?)(?=<div\s+[^>]*id="modal-content-\d+"|$)/gi;

  for (const match of html.matchAll(modalPattern)) {
    const id = match[1];
    const block = match[2];

    if (!id || !block) {
      continue;
    }

    records.push(parseModal(id, block));
  }

  records.sort((left, right) => Number(right.id) - Number(left.id));
  return records;
}

async function readInput(options: CliOptions): Promise<string> {
  if (options.file) {
    return Bun.file(options.file).text();
  }

  const sourceUrl = options.url ?? Bun.env.SOURCE_URL;
  if (!sourceUrl) {
    throw new Error("No input provided. Use --file, --url, or set SOURCE_URL.");
  }

  const response = await fetch(sourceUrl);

  if (!response.ok) {
    throw new Error(`Failed to fetch ${sourceUrl}: ${response.status} ${response.statusText}`);
  }

  return response.text();
}

async function main(): Promise<void> {
  const options = parseArgs(process.argv.slice(2));
  const html = await readInput(options);
  const reports = parseThreatReports(html);
  const output = JSON.stringify(reports, null, 2);

  if (options.out) {
    await Bun.write(options.out, output + "\n");
    console.log(`Extracted ${reports.length} reports to ${options.out}`);
    return;
  }

  console.log(output);
}

if (import.meta.main) {
  main().catch((error) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exit(1);
  });
}