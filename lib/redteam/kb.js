/**
 * ARTEX 知识库（0.4.4）只读查询层
 *
 * 数据：`knowledge/artex/knowledge.db`（poc 表 700 条 + poc_fts FTS5 索引）、
 *       `markdown/*.md`（逐条完整笔记）、`pocs/<code>/`（可用 PoC 文件）。
 *
 * 约定：
 *   · 只读打开（readOnly），不写库，不改用户数据；
 *   · 中文查询走 LIKE（FTS5 的分词对 CJK 不友好，实测「权限绕过」命中 0），
 *     英文/编号类关键词再叠一层 FTS 排序，两条结果合并去重；
 *   · 找不到库就返回空结果 + 明确原因，不抛异常打断工具调用链。
 */
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs'
import { DatabaseSync } from 'node:sqlite'
import { homedir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const PKG_KB = fileURLToPath(new URL('../../knowledge/artex', import.meta.url))
const KB_SUBDIR = join('redteam', 'knowledge', 'artex')

let handle = null

function kbRoots() {
  const homes = []
  if (process.env.DSH_HOME) homes.push(process.env.DSH_HOME)
  homes.push(join(homedir(), '.dsh'))
  const roots = homes.map((home) => join(home, KB_SUBDIR))
  roots.push(PKG_KB)
  return roots
}

function locate() {
  for (const root of kbRoots()) {
    const db = join(root, 'knowledge.db')
    if (existsSync(db)) return { root, db, size: statSync(db).size }
  }
  return null
}

function open() {
  if (handle && existsSync(handle.db)) return handle
  const found = locate()
  if (!found) return null
  try {
    handle = { ...found, dbh: new DatabaseSync(found.db, { readOnly: true }) }
  } catch {
    handle = null
  }
  return handle
}

function pad4(id) {
  return String(id).padStart(4, '0')
}

/** 读同目录 markdown/<0001_xxx>.md，找不到返回 ''。 */
function markdownOf(root, id) {
  if (!root || !id) return ''
  const dir = join(root, 'markdown')
  if (!existsSync(dir)) return ''
  const prefix = `${pad4(id)}_`
  try {
    const name = readdirSync(dir).find((f) => f.startsWith(prefix) && f.endsWith('.md'))
    if (!name) return ''
    return readFileSync(join(dir, name), 'utf8')
  } catch {
    return ''
  }
}

const SEARCH_COLUMNS = 'id, code, title, kind, category, cve, component, versions, severity, language, source, source_url, verified, hit_count, tags, path'

function shape(row, extra = {}) {
  if (!row) return null
  return {
    id: row.id,
    code: row.code,
    title: row.title,
    kind: row.kind,
    category: row.category,
    cve: row.cve || null,
    component: row.component || null,
    versions: row.versions || null,
    severity: row.severity || null,
    language: row.language || null,
    source: row.source || null,
    source_url: row.source_url || null,
    verified: Boolean(row.verified),
    hits: row.hit_count || 0,
    tags: row.tags || '',
    path: row.path || null,
    ...extra,
  }
}

/** 库状态：路径、条数、分类分布。 */
export function kbStatus() {
  const found = locate()
  if (!found) {
    return { ok: false, error: 'knowledge.db 未找到', searched: kbRoots() }
  }
  const h = open()
  if (!h) return { ok: false, error: 'node:sqlite 不可用，无法打开 knowledge.db', path: found.db }
  try {
    const total = h.dbh.prepare('select count(*) as c from poc').get().c
    const cats = h.dbh.prepare('select category, count(*) as c from poc group by category order by c desc limit 12').all()
    return { ok: true, path: found.db, bytes: found.size, entries: total, categories: cats }
  } catch (error) {
    return { ok: false, error: error && error.message ? error.message : String(error), path: found.db }
  }
}

/**
 * 关键词检索。中文走 LIKE，英文关键词额外叠 FTS 命中。
 * @param {{ query: string, limit?: number, kind?: string, category?: string }} options
 */
export function searchKb(options = {}) {
  const query = String(options.query || '').trim()
  const limit = Math.max(1, Math.min(50, Number(options.limit) || 10))
  const h = open()
  if (!h) return { ok: false, error: 'knowledge.db 不可用', entries: [] }
  if (!query) return { ok: true, query, entries: [], note: 'query 为空：调用 kb_status 可看全库分类分布' }

  const like = `%${query.replace(/[%_]/g, (m) => '\\' + m)}%`
  const filters = []
  const params = []
  if (options.kind) { filters.push('kind = ?'); params.push(String(options.kind)) }
  if (options.category) { filters.push('category = ?'); params.push(String(options.category)) }
  const where = filters.length ? ' and ' + filters.join(' and ') : ''

  let rows = []
  try {
    rows = h.dbh.prepare(
      `select ${SEARCH_COLUMNS}, substr(coalesce(description,''),1,220) as snippet
       from poc
       where (title like ? escape '\\' or code like ? escape '\\' or tags like ? escape '\\'
              or description like ? escape '\\' or cve like ? escape '\\' or component like ? escape '\\')${where}
       order by verified desc, hit_count desc, id asc
       limit ?`,
    ).all(like, like, like, like, like, like, ...params, limit)
  } catch (error) {
    return { ok: false, error: error && error.message ? error.message : String(error), entries: [] }
  }

  /* 英文/编号关键词再走 FTS：查询串只保留字母数字与连字符，避免 MATCH 语法错误。 */
  const fts = String(query).replace(/[^\p{L}\p{N}\s-]+/gu, ' ').trim()
  if (fts && rows.length < limit) {
    try {
      const tokens = fts.split(/\s+/).filter(Boolean).map((t) => `"${t}"*`).join(' ')
      const hits = h.dbh.prepare(
        `select p.${SEARCH_COLUMNS.replace(/, /g, ', p.')}, substr(coalesce(p.description,''),1,220) as snippet
         from poc_fts f join poc p on p.id = f.poc_id
         where poc_fts match ?
         order by p.verified desc, p.hit_count desc, p.id asc
         limit ?`,
      ).all(tokens, limit)
      const seen = new Set(rows.map((r) => r.id))
      for (const hit of hits) if (!seen.has(hit.id)) rows.push(hit)
      rows = rows.slice(0, limit)
    } catch { /* FTS 不可用就当没有，LIKE 已经给出结果 */ }
  }

  return {
    ok: true,
    query,
    kb: { path: h.db, entries: rows.length },
    entries: rows.map((row) => shape(row, { snippet: row.snippet || '' })),
    hint: '拿到 code 后用 redteam_kb_get 取完整正文与 PoC 文件路径；markdown 全文在 knowledge/artex/markdown/ 下。',
  }
}

/**
 * 取单条完整记录（按 code 或 id）。
 * @param {{ code?: string, id?: number, include_content?: boolean }} options
 */
export function getKb(options = {}) {
  const h = open()
  if (!h) return { ok: false, error: 'knowledge.db 不可用' }
  let row = null
  try {
    if (options.code) {
      row = h.dbh.prepare(`select ${SEARCH_COLUMNS}, description, usage, content, verified_note, used_on, engagement_name, asset_target, found_by_agent, created_at, updated_at from poc where code = ? limit 1`).get(String(options.code))
    } else if (options.id !== undefined && options.id !== null) {
      row = h.dbh.prepare(`select ${SEARCH_COLUMNS}, description, usage, content, verified_note, used_on, engagement_name, asset_target, found_by_agent, created_at, updated_at from poc where id = ? limit 1`).get(Number(options.id))
    }
  } catch (error) {
    return { ok: false, error: error && error.message ? error.message : String(error) }
  }
  if (!row) return { ok: false, error: '未找到该条目', code: options.code ?? null, id: options.id ?? null }

  const includeContent = options.include_content !== false
  const content = includeContent ? String(row.content || '') : ''
  const md = markdownOf(h.root, row.id)
  const pocFile = row.path ? (existsSync(join(h.root, row.path)) ? join(h.root, row.path) : row.path) : null

  return {
    ok: true,
    entry: shape(row, {
      description: row.description || '',
      usage: row.usage || '',
      verified_note: row.verified_note || null,
      used_on: row.used_on || null,
      engagement: row.engagement_name || null,
      asset_target: row.asset_target || null,
      found_by_agent: row.found_by_agent || null,
      created_at: row.created_at || null,
      updated_at: row.updated_at || null,
      content: content.length > 6000 ? content.slice(0, 6000) + '\n…（已截断，完整内容见 content_path / markdown_path）' : content,
      poc_file: pocFile,
      markdown_path: md ? join(h.root, 'markdown') : null,
      markdown: md.length > 8000 ? md.slice(0, 8000) + '\n…（已截断）' : md,
    }),
  }
}

/** 供面板/工具共用的库根目录（找不到时给候选路径）。 */
export function kbRoot() {
  const found = locate()
  return found ? found.root : kbRoots()[0]
}