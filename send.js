import { AttachmentBuilder, WebhookClient } from "discord.js";
import countries from "i18n-iso-countries";
import enLocale from "i18n-iso-countries/langs/en.json";
import { nationalityToCountry } from "demonym";
import sharp from "sharp";

const FORUMS_PATH = "./forums.json";
const LOGS_PATH = "./logs.txt";
const DEFAULT_MAX_IMAGE_BYTES = 1_048_576;

countries.registerLocale(enLocale);

const COUNTRY_NAME_TO_ALPHA2 = new Map(
  Object.entries(countries.getNames("en")).map(([alpha2, name]) => [
    String(name).toLowerCase(),
    alpha2.toLowerCase(),
  ]),
);

const COUNTRY_ALIASES = {
  usa: "us",
  uae: "ae",
  uk: "gb",
};

function normalizeValue(value) {
  if (value === null || value === undefined) {
    return "N/A";
  }

  const text = String(value).trim();
  return text.length > 0 ? text : "N/A";
}

function obfuscateUrl(url) {
  const value = normalizeValue(url);
  if (value === "N/A") {
    return value;
  }

  return value.replace(/^https:\/\//i, "hxxps://").replace(/^http:\/\//i, "hxxp://");
}

function formatHumanDate(value) {
  const normalized = normalizeValue(value);
  if (normalized === "N/A") {
    return normalized;
  }

  const match = normalized.match(/^(\d{4})-(\d{2})-(\d{2})$/);
  if (!match) {
    return normalized;
  }

  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const date = new Date(Date.UTC(year, month - 1, day));

  if (
    Number.isNaN(date.getTime()) ||
    date.getUTCFullYear() !== year ||
    date.getUTCMonth() + 1 !== month ||
    date.getUTCDate() !== day
  ) {
    return normalized;
  }

  return new Intl.DateTimeFormat("en-US", {
    year: "numeric",
    month: "long",
    day: "numeric",
    timeZone: "UTC",
  }).format(date);
}

function resolveCountryCode(originValue) {
  const origin = normalizeValue(originValue);
  if (origin === "N/A") {
    return null;
  }

  const primary = origin
    .split(/[\/,|]/)[0]
    ?.trim()
    .toLowerCase()
    .replace(/[^a-z ]/g, "")
    .replace(/\s+/g, " ");

  if (!primary) {
    return null;
  }

  if (/^[a-z]{2}$/.test(primary)) {
    return primary;
  }

  if (/^[a-z]{3}$/.test(primary)) {
    const alpha2 = countries.alpha3ToAlpha2(primary.toUpperCase());
    return alpha2 ? alpha2.toLowerCase() : null;
  }

  const aliased = COUNTRY_ALIASES[primary];
  if (aliased) {
    return aliased;
  }

  const byName = COUNTRY_NAME_TO_ALPHA2.get(primary);
  if (byName) {
    return byName;
  }

  const demonymResolved = nationalityToCountry(primary) ?? nationalityToCountry(primary.replace(/s$/, ""));
  if (demonymResolved?.code) {
    return demonymResolved.code.toLowerCase();
  }

  return null;
}

function extensionFromMime(mimeType) {
  const subtype = mimeType.split("/")[1] ?? "png";
  const normalized = subtype.toLowerCase();
  if (normalized === "jpeg") {
    return "jpg";
  }
  if (normalized.includes("svg")) {
    return "svg";
  }
  if (normalized.includes("webp")) {
    return "webp";
  }
  if (normalized.includes("gif")) {
    return "gif";
  }
  return "png";
}

function maxImageBytes() {
  const configured = Number.parseInt(String(Bun.env.MAX_IMAGE_BYTES ?? ""), 10);
  if (Number.isFinite(configured) && configured > 0) {
    return configured;
  }

  return DEFAULT_MAX_IMAGE_BYTES;
}

async function compressImageIfNeeded(buffer, mimeType) {
  const threshold = maxImageBytes();
  if (buffer.byteLength <= threshold) {
    return { buffer, extension: extensionFromMime(mimeType) };
  }

  const qualityLevels = [82, 72, 62, 52];
  const scales = [1, 0.85, 0.7, 0.55];

  let bestBuffer = buffer;
  let metadata;

  try {
    metadata = await sharp(buffer, { failOn: "none" }).metadata();
  } catch {
    return { buffer, extension: extensionFromMime(mimeType) };
  }

  const width = metadata?.width ?? null;

  for (const scale of scales) {
    for (const quality of qualityLevels) {
      try {
        let pipeline = sharp(buffer, { failOn: "none" }).rotate();
        if (width && scale < 1) {
          pipeline = pipeline.resize({
            width: Math.max(320, Math.round(width * scale)),
            withoutEnlargement: true,
          });
        }

        const candidate = await pipeline.webp({ quality, effort: 4 }).toBuffer();
        if (candidate.byteLength < bestBuffer.byteLength) {
          bestBuffer = candidate;
        }

        if (candidate.byteLength <= threshold) {
          return { buffer: candidate, extension: "webp" };
        }
      } catch {
        continue;
      }
    }
  }

  const finalExtension = bestBuffer === buffer ? extensionFromMime(mimeType) : "webp";
  return { buffer: bestBuffer, extension: finalExtension };
}

async function buildImageAttachment(imageValue, recordId) {
  const image = normalizeValue(imageValue);
  if (image === "N/A") {
    return { files: [], imageUrl: null };
  }

  const dataUrlMatch = image.match(/^data:(image\/[\w.+-]+);base64,(.+)$/i);
  if (dataUrlMatch) {
    const mimeType = dataUrlMatch[1];
    const encoded = dataUrlMatch[2];
    const source = Buffer.from(encoded, "base64");
    const processed = await compressImageIfNeeded(source, mimeType);
    const extension = processed.extension;
    const fileName = `threat-${recordId}.${extension}`;
    const file = new AttachmentBuilder(processed.buffer, {
      name: fileName,
    });

    return {
      files: [file],
      imageUrl: `attachment://${fileName}`,
    };
  }

  if (/^https?:\/\//i.test(image) && image.length <= 2048) {
    return { files: [], imageUrl: image };
  }

  return { files: [], imageUrl: null };
}

async function readJson(path) {
  const text = await Bun.file(path).text();
  return JSON.parse(text);
}

async function readSentIds() {
  const file = Bun.file(LOGS_PATH);
  if (!(await file.exists())) {
    return new Set();
  }

  const raw = await file.text();
  return new Set(
    raw
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean),
  );
}

async function buildPayload(record) {
  const id = String(record?.id ?? "unknown");
  const image = await buildImageAttachment(record.image, id);
  const roleId = String(Bun.env.DISCORD_ROLE_ID ?? "").trim();
  const content = roleId ? `<@&${roleId}>` : "";
  const countryCode = resolveCountryCode(record.origin);
  const fields = [
    {
      name: "Date",
      value: formatHumanDate(record.timestamp),
      inline: true,
    },
    {
      name: "Actor",
      value: normalizeValue(record.threatActor),
      inline: false,
    },
    {
      name: "Origin",
      value: normalizeValue(record.origin),
      inline: false,
    },
    {
      name: "Sector",
      value: normalizeValue(record.sector),
      inline: true,
    },
    {
      name: "Source",
      value: obfuscateUrl(record.sourceUrl),
      inline: false,
    },
  ];

  const embed = {
    title: normalizeValue(record.title),
    color: 2326507,
    fields,
  };

  if (countryCode) {
    embed.thumbnail = {
      url: `https://flagcdn.com/48x36/${countryCode}.png`,
    };
  }

  if (image.imageUrl) {
    embed.image = { url: image.imageUrl };
  }

  return {
    content,
    tts: false,
    embeds: [embed],
    files: image.files,
  };
}

async function appendSentId(id) {
  const file = Bun.file(LOGS_PATH);
  const existing = (await file.exists()) ? await file.text() : "";
  const suffix = existing.endsWith("\n") || existing.length === 0 ? "" : "\n";
  await Bun.write(LOGS_PATH, `${existing}${suffix}${id}\n`);
}

async function main() {
  const webhookUrl = Bun.env.DISCORD_WEBHOOK_URL;
  if (!webhookUrl) {
    throw new Error("DISCORD_WEBHOOK_URL is missing in environment");
  }

  const [records, sentIds] = await Promise.all([
    readJson(FORUMS_PATH),
    readSentIds(),
  ]);

  if (!Array.isArray(records)) {
    throw new Error("forums.json must be an array");
  }

  const webhook = new WebhookClient({ url: webhookUrl });

  let sentCount = 0;
  let skippedCount = 0;

  for (const record of records) {
    const id = String(record?.id ?? "").trim();
    if (!id) {
      continue;
    }

    if (sentIds.has(id)) {
      skippedCount += 1;
      continue;
    }

    const payload = await buildPayload(record);
    await webhook.send(payload);
    await appendSentId(id);
    sentIds.add(id);
    sentCount += 1;

    console.log(`Sent ${id}`);
  }

  await webhook.destroy();
  console.log(`Done. Sent: ${sentCount}, skipped (already sent): ${skippedCount}`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});