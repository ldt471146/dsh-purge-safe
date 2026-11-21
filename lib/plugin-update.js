/**
 * 版本可选的自更新（插件自身）。
 *
 * 设计边界，别越界：
 * - 只做「列版本 + 装指定版本 + 覆盖插件目录」，**不碰宿主文件、不重打破甲补丁、不自动重启**。
 *   宿主侧的补丁重打由 lib/reapply.js 在下次启动时自己完成，这里硬插一脚只会把顺序搞乱。
 * - 不用 GitHub API 做必需路径：未认证 60 次/小时会被限流。版本清单走 `git ls-remote`
 *   （无限流），版本号走 raw.githubusercontent，时间走 releases.atom；三者任一失败都不影响主流程。
 * - 下载走 codeload zip（固定 commit，不怕 tag 被挪），解压复用本仓的 zip-extract。
 */
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { atomicWriteSync } from "./core.js";
import { extractZipArchive } from "./zip-extract.js";

const PLUGIN_ROOT = path.resolve(fileURLToPath(new URL(".", import.meta.url)), "..");
export const REPO = String(process.env.DSH_PURGE_UPDATE_REPO || "ldt471146/dsh-purge-safe").trim();
const PACKAGE_NAME = "dsh-purge-safe";
const REF_OK = /^[A-Za-z0-9][A-Za-z0-9._/-]{0,99}$/;
const SHA_OK = /^[0-9a-f]{7,40}$/i;
const MAX_ZIP_BYTES = 96 * 1024 * 1024;
const LIST_TTL_MS = 60 * 1000;
const SKIP_DIRS = new Set(["node_modules", ".git"]);

/** 进程启动时磁盘上的版本 —— 用来判断「装了新版但要重启才生效」。 */
const RUNNING_VERSION = readDiskVersion();

function readJson(file) {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    return null;
  }
}

function readDiskVersion() {
  const pkg = readJson(path.join(PLUGIN_ROOT, "package.json"));
  return pkg && typeof pkg.version === "string" ? pkg.version : "";
}

function readInstalledRev() {
  try {
    return fs.readFileSync(path.join(pluginStateDir(), "installed-rev"), "utf8").trim();
  } catch {
    return "";
  }
}

function pluginStateDir() {
  const home = process.env.DSH_HOME && process.env.DSH_HOME.trim()
    ? process.env.DSH_HOME.trim()
    : path.join(os.homedir(), ".dsh");
  return path.join(home, PACKAGE_NAME);
}

function ensureDir(dir) {
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

export function pluginRoot() {
  return PLUGIN_ROOT;
}

export function normalizeRef(ref) {
  const text = String(ref || "").trim();
  if (!text) return "";
  if (SHA_OK.test(text)) return text.toLowerCase();
  if (!REF_OK.test(text) || text.includes("..")) return "";
  return text;
}

/** tag 名 → 展示版本：v2.1.1 → 2.1.1；main 之类保留原名。 */
export function versionOfRef(ref, kind) {
  const text = String(ref || "");
  if (kind === "tag" && /^v?\d+\.\d+/.test(text)) return text.replace(/^v/i, "");
  return "";
}

async function httpText(url, ms = 8000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ms);
  try {
    const res = await fetch(url, {
      signal: controller.signal,
      headers: { "user-agent": `${PACKAGE_NAME}-updater`, accept: "*/*" },
      redirect: "follow",
    });
    if (!res.ok) return "";
    return await res.text();
  } catch {
    return "";
  } finally {
    clearTimeout(timer);
  }
}

function gitLsRemote() {
  try {
    const out = execFileSync(
      "git",
      ["ls-remote", "--tags", "--heads", `https://github.com/${REPO}.git`],
      { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"], timeout: 20000, windowsHide: true },
    );
    return String(out || "");
  } catch {
    return "";
  }
}

/** `git ls-remote` 输出 → [{ref, kind, sha}]，annotated tag 取 peeled sha。 */
export function parseLsRemote(text) {
  const tags = new Map();
  const heads = [];
  for (const line of String(text || "").split(/\r?\n/)) {
    const [sha, ref] = line.trim().split(/\s+/);
    if (!sha || !ref) continue;
    if (ref.startsWith("refs/tags/")) {
      const name = ref.slice("refs/tags/".length);
      const peeled = name.endsWith("^{}");
      const key = peeled ? name.slice(0, -3) : name;
      const prev = tags.get(key);
      if (peeled || !prev) tags.set(key, { ref: key, kind: "tag", sha: sha.toLowerCase() });
      void prev;
    } else if (ref.startsWith("refs/heads/")) {
      heads.push({ ref: ref.slice("refs/heads/".length), kind: "head", sha: sha.toLowerCase() });
    }
  }
  return [...tags.values(), ...heads];
}

/** releases.atom 里的发布时间，不占 API 配额。 */
async function releaseDates() {
  const text = await httpText(`https://github.com/${REPO}/releases.atom`, 8000);
  const dates = new Map();
  if (!text) return dates;
  const entries = text.split("<entry>").slice(1);
  for (const entry of entries) {
    const updated = /<updated>([^<]+)<\/updated>/u.exec(entry);
    const link = /releases\/tag\/([^"<]+)/u.exec(entry);
    if (!updated || !link) continue;
    dates.set(decodeURIComponent(link[1]), updated[1]);
  }
  return dates;
}

function rawPackageVersion(sha) {
  return httpText(`https://raw.githubusercontent.com/${REPO}/${sha}/package.json`, 8000).then((text) => {
    if (!text) return "";
    try {
      const pkg = JSON.parse(text);
      return typeof pkg.version === "string" ? pkg.version : "";
    } catch {
      return "";
    }
  });
}

let listCache = { at: 0, value: null };
let listInflight = null;

export async function listVersions({ force = false } = {}) {
  const now = Date.now();
  if (!force && listCache.value && now - listCache.at < LIST_TTL_MS) return listCache.value;
  if (listInflight) return listInflight;
  listInflight = (async () => {
    const raw = gitLsRemote();
    const entries = parseLsRemote(raw);
    const dates = await releaseDates().catch(() => new Map());
    const local = readDiskVersion();
    const installedRev = readInstalledRev();
    const versions = [];
    for (const entry of entries) {
      let version = versionOfRef(entry.ref, entry.kind);
      if (!version && entry.kind === "head") version = await rawPackageVersion(entry.sha).catch(() => "");
      const at = dates.get(entry.ref) || dates.get(`v${version}`) || "";
      versions.push({
        ref: entry.ref,
        kind: entry.kind,
        sha: entry.sha,
        short: entry.sha.slice(0, 7),
        version,
        at,
        channel: entry.kind === "head" ? "branch" : (/-(?:beta|rc|pre|alpha)/i.test(version) ? "pre" : "stable"),
        /* 「当前」只认磁盘版本号；installed-rev 只在拿不到版本号时兜底。
           以前一律 endsWith(sha)，装过一次别的版本后会把旧 tag 也标成「当前」。 */
        current: version && local
          ? version === local
          : Boolean(installedRev && installedRev.endsWith(entry.sha)),
        downloadable: true,
      });
    }
    /* 版本新的排前面：先 semver 倒序，再 tag 优先于分支 */
    const weight = (item) => {
      const nums = String(item.version || "").split("-")[0].split(".").map((n) => parseInt(n, 10) || 0);
      return (nums[0] || 0) * 1e6 + (nums[1] || 0) * 1e3 + (nums[2] || 0);
    };
    versions.sort((a, b) => {
      if (a.kind !== b.kind) return a.kind === "tag" ? -1 : 1;
      if (weight(a) !== weight(b)) return weight(b) - weight(a);
      return a.ref.localeCompare(b.ref);
    });
    if (!versions.some((item) => item.current) && local) {
      versions.unshift({
        ref: 'local:' + local,
        kind: 'local',
        sha: '',
        short: '',
        version: local,
        at: '',
        channel: 'local',
        current: true,
        downloadable: false,
      })
    }
    const value = {
      ok: true,
      repo: REPO,
      source: raw ? "git" : "offline",
      current: local,
      runningVersion: RUNNING_VERSION,
      pendingRestart: Boolean(local && RUNNING_VERSION && local !== RUNNING_VERSION),
      installedRev,
      versions,
      fetchedAt: new Date().toISOString(),
      error: raw ? undefined : "无法读取远端版本清单（网络或 git 不可用）",
    };
    listCache = { at: Date.now(), value };
    return value;
  })();
  try {
    return await listInflight;
  } finally {
    listInflight = null;
  }
}

async function downloadZip(sha, dest) {
  const url = `https://codeload.github.com/${REPO}/zip/${sha}`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 120000);
  try {
    const res = await fetch(url, {
      signal: controller.signal,
      headers: { "user-agent": `${PACKAGE_NAME}-updater` },
      redirect: "follow",
    });
    if (!res.ok) throw new Error(`下载失败 HTTP ${res.status}`);
    const buf = Buffer.from(await res.arrayBuffer());
    if (buf.length === 0) throw new Error("下载内容为空");
    if (buf.length > MAX_ZIP_BYTES) throw new Error(`包过大 ${buf.length} 字节`);
    fs.writeFileSync(dest, buf);
    return buf.length;
  } catch (error) {
    throw new Error(`下载 ${sha.slice(0, 7)} 失败：${error && error.message ? error.message : String(error)}`);
  } finally {
    clearTimeout(timer);
  }
}

function copyTree(src, dest) {
  let files = 0;
  let bytes = 0;
  const walk = (from, to) => {
    for (const entry of fs.readdirSync(from, { withFileTypes: true })) {
      if (SKIP_DIRS.has(entry.name)) continue;
      const s = path.join(from, entry.name);
      const d = path.join(to, entry.name);
      if (entry.isDirectory()) {
        ensureDir(d);
        walk(s, d);
        continue;
      }
      if (entry.isSymbolicLink()) continue;
      if (!entry.isFile()) continue;
      ensureDir(path.dirname(d));
      const data = fs.readFileSync(s);
      const tmp = `${d}.dshtmp-${process.pid}`;
      fs.writeFileSync(tmp, data);
      fs.renameSync(tmp, d);
      files += 1;
      bytes += data.length;
    }
  };
  walk(src, dest);
  return { files, bytes };
}

export async function installVersion(ref) {
  const target = normalizeRef(ref);
  if (!target) return { ok: false, error: "版本号不合法" };
  const listed = await listVersions({ force: true });
  const hit = (listed.versions || []).find((item) => (
    item.ref === target || item.sha === target || item.short === target
  ));
  if (!hit) return { ok: false, error: `版本清单里没有 ${target}`, versions: listed.versions };
  if (hit.current) {
    return { ok: true, unchanged: true, version: hit.version, ref: hit.ref, sha: hit.sha, needRestart: false };
  }

  const fromVersion = readDiskVersion();
  const work = ensureDir(fs.mkdtempSync(path.join(os.tmpdir(), "dsh-purge-update-")));
  const zip = path.join(work, "pkg.zip");
  let stage = "";
  try {
    const bytes = await downloadZip(hit.sha, zip);
    const unzipped = ensureDir(path.join(work, "src"));
    extractZipArchive(zip, unzipped);
    const roots = fs.readdirSync(unzipped, { withFileTypes: true }).filter((e) => e.isDirectory());
    if (roots.length !== 1) throw new Error("压缩包结构不对（应只有一个顶层目录）");
    stage = path.join(unzipped, roots[0].name);
    const pkg = readJson(path.join(stage, "package.json"));
    if (!pkg || pkg.name !== PACKAGE_NAME) throw new Error("下载的包不是 dsh-purge-safe");
    if (!fs.existsSync(path.join(stage, "cordis.patch.yml"))) throw new Error("下载的包缺少组合包补丁");

    /* 备份：整棵旧树（不含 node_modules/.git），出问题直接拷回来 */
    const backup = ensureDir(path.join(pluginStateDir(), `pre-update-${Date.now()}`));
    copyTree(PLUGIN_ROOT, backup);
    const copied = copyTree(stage, PLUGIN_ROOT);

    const toVersion = typeof pkg.version === "string" ? pkg.version : "";
    atomicWriteSync(path.join(pluginStateDir(), "installed-rev"), `update:${hit.sha}\n`);
    atomicWriteSync(path.join(pluginStateDir(), "last-update.json"), `${JSON.stringify({
      ref: hit.ref,
      sha: hit.sha,
      version: toVersion,
      fromVersion,
      at: new Date().toISOString(),
      backup,
      files: copied.files,
    }, null, 2)}\n`);
    listCache = { at: 0, value: null };
    return {
      ok: true,
      ref: hit.ref,
      sha: hit.sha,
      short: hit.short,
      fromVersion,
      version: toVersion,
      files: copied.files,
      bytes,
      backup,
      needRestart: true,
    };
  } catch (error) {
    return {
      ok: false,
      ref: hit.ref,
      sha: hit.sha,
      fromVersion,
      error: error && error.message ? error.message : String(error),
    };
  } finally {
    try {
      fs.rmSync(work, { recursive: true, force: true });
    } catch {
      /* 临时目录清不掉不影响结果 */
    }
  }
}

export function updateStatus() {
  const local = readDiskVersion();
  return {
    ok: true,
    repo: REPO,
    current: local,
    runningVersion: RUNNING_VERSION,
    pendingRestart: Boolean(local && RUNNING_VERSION && local !== RUNNING_VERSION),
    installedRev: readInstalledRev(),
    stateDir: pluginStateDir(),
    lastUpdate: readJson(path.join(pluginStateDir(), "last-update.json")),
  };
}