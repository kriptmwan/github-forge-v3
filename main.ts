// github-forge-v3: a standalone GitHub-compatible git forge in one process.
//
// Serves git smart HTTP (upload-pack v2, receive-pack v0), REST v3, GraphQL v4
// and MCP over streamable HTTP, all from an in-memory store with real git
// objects. Node 22, standard library only, no dependencies.
//
// Lifecycle: bind an ephemeral port, POST {"port"} to $MAKEFUN_ENV_URL/register,
// poll GET $MAKEFUN_ENV_URL/done until {"done": true}, exit 0. With no env URL
// set the server just serves (local practice mode).

import http from 'node:http';
import { createServer } from 'node:http';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { createHash } from 'node:crypto';
import { deflateSync, inflateSync } from 'node:zlib';

// ---------------------------------------------------------------- constants

const VIEWER_LOGIN = 'adaiversen';
const VIEWER_ID = 1000;
const VIEWER_NAME = 'ada iversen';
const VIEWER_EMAIL = 'adaiversen@example.invalid';
const STRANGER_LOGIN = 'olgabauer';
const DEFAULT_BRANCH = 'main';
const ZERO_OID = '0'.repeat(40);
const AGENT = 'github-forge-v3/1.0';
const VERSION = '1.0.0';
// The trial clock, read once at module load; every timestamp derives from it.
const EPOCH_MS = Date.now();
// The bearer token, read once at load.
const TOKEN: string = process.env.MAKEFUN_SHOP_TOKEN ?? 'local-dev-token';
const ENV_URL: string = (process.env.MAKEFUN_ENV_URL ?? '').replace(/\/+$/, '');
const COMMIT_IDENTITY = `${VIEWER_NAME} <${VIEWER_EMAIL}>`;
const FIXED_COMMIT_TS = 1700000000;

let requestSeq = 0;
let globalSeq = 0;
let nextRepoId = 1;
let nextIssueId = 1;
let nextCommentId = 1;
let nextPullId = 1;

function nextSeq(): number {
  globalSeq += 1;
  return globalSeq;
}

function isoTs(seq: number): string {
  return new Date(EPOCH_MS + seq * 1000).toISOString();
}

function requestId(): string {
  requestSeq += 1;
  return `req-${requestSeq.toString(36)}-${Date.now().toString(36)}`;
}

// ---------------------------------------------------------------- utilities

function sha1Hex(data: Buffer): string {
  return createHash('sha1').update(data).digest('hex');
}

function objectHeader(type: string, size: number): Buffer {
  return Buffer.from(`${type} ${size}\u0000`, 'utf8');
}

export function hashObject(type: string, data: Buffer): string {
  const h = createHash('sha1');
  h.update(objectHeader(type, data.length));
  h.update(data);
  return h.digest('hex');
}

function isOid(v: string): boolean {
  return /^[0-9a-f]{40}$/.test(v);
}

function b64encode(buf: Buffer): string {
  return buf.toString('base64');
}

function b64decode(text: string): Buffer {
  return Buffer.from(text.replace(/[\r\n\t ]+/g, ''), 'base64');
}

function gid(kind: string, n: number): string {
  return Buffer.from(`${kind}:${n}`, 'utf8').toString('base64');
}

function parseGid(id: string): { kind: string; num: number } | null {
  try {
    const text = Buffer.from(id, 'base64').toString('utf8');
    const i = text.indexOf(':');
    if (i < 0) return null;
    const n = Number(text.slice(i + 1));
    if (!Number.isInteger(n) || n <= 0) return null;
    return { kind: text.slice(0, i), num: n };
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------- pkt-line

function pktLine(payload: string | Buffer): Buffer {
  const data = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : payload;
  const head = Buffer.allocUnsafe(4);
  head.write((data.length + 4).toString(16).padStart(4, '0'), 0, 4, 'ascii');
  return Buffer.concat([head, data]);
}

const PKT_FLUSH = Buffer.from('0000', 'ascii');
const PKT_DELIM = Buffer.from('0001', 'ascii');

function pktLines(items: Array<string | Buffer | 'flush' | 'delim'>): Buffer {
  const parts: Buffer[] = [];
  for (const item of items) {
    if (item === 'flush') parts.push(PKT_FLUSH);
    else if (item === 'delim') parts.push(PKT_DELIM);
    else parts.push(pktLine(item));
  }
  return Buffer.concat(parts);
}

type Pkt = { kind: 'data'; payload: Buffer } | { kind: 'flush' } | { kind: 'delim' } | { kind: 'end' };

function decodePktLines(buf: Buffer): Pkt[] {
  const out: Pkt[] = [];
  let off = 0;
  while (off + 4 <= buf.length) {
    const head = buf.subarray(off, off + 4).toString('ascii');
    if (!/^[0-9a-fA-F]{4}$/.test(head)) break; // raw bytes follow (a pack)
    const len = parseInt(head, 16);
    if (len === 0) {
      out.push({ kind: 'flush' });
      off += 4;
    } else if (len === 1) {
      out.push({ kind: 'delim' });
      off += 4;
    } else if (len === 2) {
      out.push({ kind: 'end' });
      off += 4;
    } else if (len === 3 || len > 65520 || off + len > buf.length) {
      break;
    } else {
      out.push({ kind: 'data', payload: buf.subarray(off + 4, off + len) });
      off += len;
    }
  }
  return out;
}

// Split a request body into its pkt-line section and the raw tail (pack bytes).
function splitPktAndRaw(buf: Buffer): { packets: Pkt[]; rawAt: number } {
  const packets: Pkt[] = [];
  let off = 0;
  while (off + 4 <= buf.length) {
    const head = buf.subarray(off, off + 4).toString('ascii');
    if (!/^[0-9a-fA-F]{4}$/.test(head)) break;
    const len = parseInt(head, 16);
    if (len === 0) {
      packets.push({ kind: 'flush' });
      off += 4;
      // After the first flush in a receive-pack body, a pack follows.
      break;
    }
    if (len === 1) {
      packets.push({ kind: 'delim' });
      off += 4;
      continue;
    }
    if (len === 2) {
      packets.push({ kind: 'end' });
      off += 4;
      continue;
    }
    if (len === 3 || len > 65520 || off + len > buf.length) break;
    packets.push({ kind: 'data', payload: buf.subarray(off + 4, off + len) });
    off += len;
  }
  return { packets, rawAt: off };
}

// ---------------------------------------------------------------- git objects

type ObjType = 'commit' | 'tree' | 'blob' | 'tag';
interface GitObj {
  type: ObjType;
  data: Buffer;
}
interface TreeEntry {
  mode: string;
  name: string;
  oid: string;
}
interface CommitView {
  tree: string;
  parents: string[];
  author: string;
  committer: string;
  message: string;
}

function parseTree(data: Buffer): TreeEntry[] {
  const entries: TreeEntry[] = [];
  let off = 0;
  while (off < data.length) {
    const sp = data.indexOf(0x20, off);
    if (sp < 0) break;
    const nul = data.indexOf(0x00, sp + 1);
    if (nul < 0 || nul + 21 > data.length) break;
    entries.push({
      mode: data.subarray(off, sp).toString('ascii'),
      name: data.subarray(sp + 1, nul).toString('utf8'),
      oid: data.subarray(nul + 1, nul + 21).toString('hex'),
    });
    off = nul + 21;
  }
  return entries;
}

function buildTree(entries: TreeEntry[]): Buffer {
  const sorted = [...entries].sort((a, b) => {
    const la = Buffer.from(a.mode === '40000' ? `${a.name}/` : a.name, 'utf8');
    const lb = Buffer.from(b.mode === '40000' ? `${b.name}/` : b.name, 'utf8');
    return Buffer.compare(la, lb);
  });
  const parts: Buffer[] = [];
  for (const e of sorted) {
    parts.push(Buffer.from(`${e.mode} ${e.name}\u0000`, 'utf8'));
    parts.push(Buffer.from(e.oid, 'hex'));
  }
  return Buffer.concat(parts);
}

function parseCommit(data: Buffer): CommitView {
  const blank = data.indexOf('\n\n');
  const headEnd = blank < 0 ? data.length : blank;
  const message = blank < 0 ? '' : data.subarray(blank + 2).toString('utf8');
  let tree = '';
  const parents: string[] = [];
  let author = '';
  let committer = '';
  for (const line of data.subarray(0, headEnd).toString('utf8').split('\n')) {
    if (!line) continue;
    const sp = line.indexOf(' ');
    const key = sp < 0 ? line : line.slice(0, sp);
    const val = sp < 0 ? '' : line.slice(sp + 1);
    if (key === 'tree') tree = val;
    else if (key === 'parent') parents.push(val);
    else if (key === 'author') author = val;
    else if (key === 'committer') committer = val;
  }
  return { tree, parents, author, committer, message };
}

function buildCommit(tree: string, parents: string[], message: string, ts: number): Buffer {
  const who = `${COMMIT_IDENTITY} ${ts} +0000`;
  const lines = [`tree ${tree}`];
  for (const p of parents) lines.push(`parent ${p}`);
  lines.push(`author ${who}`, `committer ${who}`, '');
  return Buffer.from(`${lines.join('\n')}\n${message}`, 'utf8');
}

function parseTagTarget(data: Buffer): { object: string; type: ObjType } | null {
  const blank = data.indexOf('\n\n');
  const headEnd = blank < 0 ? data.length : blank;
  let object = '';
  let type = '';
  for (const line of data.subarray(0, headEnd).toString('utf8').split('\n')) {
    const sp = line.indexOf(' ');
    if (sp < 0) continue;
    const key = line.slice(0, sp);
    const val = line.slice(sp + 1);
    if (key === 'object') object = val;
    else if (key === 'type') type = val;
  }
  if (!isOid(object)) return null;
  if (type !== 'commit' && type !== 'tree' && type !== 'blob' && type !== 'tag') return null;
  return { object, type: type as ObjType };
}

// Resolve a tag (possibly nested) to the commit it peels to.
function peelToCommit(repo: Repo, oid: string): string | null {
  let cur = oid;
  for (let i = 0; i < 10; i += 1) {
    const obj = repo.objects.get(cur);
    if (!obj) return null;
    if (obj.type === 'commit') return cur;
    if (obj.type === 'tag') {
      const t = parseTagTarget(obj.data);
      if (!t) return null;
      cur = t.object;
    } else {
      return null;
    }
  }
  return null;
}

// Every object reachable from roots (commits -> tree+parents, tags -> target,
// trees -> entries). Missing objects are skipped when allowMissing is set.
function collectReachable(repo: Repo, roots: Iterable<string>, allowMissing = false): Set<string> {
  const seen = new Set<string>();
  const queue: string[] = [];
  for (const r of roots) if (isOid(r)) queue.push(r);
  while (queue.length) {
    const oid = queue.pop() as string;
    if (seen.has(oid)) continue;
    const obj = repo.objects.get(oid);
    if (!obj) {
      if (allowMissing) continue;
      throw new Error(`missing object ${oid}`);
    }
    seen.add(oid);
    if (obj.type === 'commit') {
      const c = parseCommit(obj.data);
      queue.push(c.tree);
      for (const p of c.parents) queue.push(p);
    } else if (obj.type === 'tag') {
      const t = parseTagTarget(obj.data);
      if (t) queue.push(t.object);
    } else if (obj.type === 'tree') {
      for (const e of parseTree(obj.data)) {
        if (e.mode !== '160000') queue.push(e.oid);
      }
    }
  }
  return seen;
}

// Is `anc` an ancestor of (or equal to) `tip`? Walks parents, bounded.
function isAncestor(repo: Repo, anc: string, tip: string): boolean {
  if (anc === tip) return true;
  const seen = new Set<string>();
  const queue = [tip];
  while (queue.length) {
    const oid = queue.pop() as string;
    if (oid === anc) return true;
    if (seen.has(oid)) continue;
    seen.add(oid);
    if (seen.size > 100000) return false;
    const obj = repo.objects.get(oid);
    if (!obj || obj.type !== 'commit') continue;
    for (const p of parseCommit(obj.data).parents) queue.push(p);
  }
  return false;
}

// ---------------------------------------------------------------- packfiles

const TYPE_CODE: Record<ObjType, number> = { commit: 1, tree: 2, blob: 3, tag: 4 };
const CODE_TYPE: Record<number, ObjType> = { 1: 'commit', 2: 'tree', 3: 'blob', 4: 'tag' };

function packObjectHeader(type: ObjType, size: number): Buffer {
  const code = TYPE_CODE[type];
  const bytes: number[] = [];
  let remaining = size;
  let first = (code << 4) | (remaining & 0x0f);
  remaining = Math.floor(remaining / 16);
  while (remaining > 0) {
    bytes.push(first | 0x80);
    first = remaining & 0x7f;
    remaining = Math.floor(remaining / 128);
  }
  bytes.push(first);
  return Buffer.from(bytes);
}

function writePack(objects: Array<{ type: ObjType; data: Buffer }>): Buffer {
  const parts: Buffer[] = [];
  const head = Buffer.allocUnsafe(12);
  head.write('PACK', 0, 4, 'ascii');
  head.writeUInt32BE(2, 4);
  head.writeUInt32BE(objects.length, 8);
  parts.push(head);
  for (const o of objects) {
    parts.push(packObjectHeader(o.type, o.data.length));
    parts.push(deflateSync(o.data));
  }
  const body = Buffer.concat(parts);
  return Buffer.concat([body, createHash('sha1').update(body).digest()]);
}

function readVarintSize(buf: Buffer, start: number): { size: number; next: number; first: number } {
  let byte = buf[start] as number;
  const first = byte;
  let size = byte & 0x0f;
  let shift = 4;
  let off = start + 1;
  while (byte & 0x80) {
    byte = buf[off] as number;
    off += 1;
    size += (byte & 0x7f) * 2 ** shift;
    shift += 7;
  }
  return { size, next: off, first };
}

function readOfsBase(buf: Buffer, start: number): { baseOffset: number; next: number } {
  let byte = buf[start] as number;
  let off = start + 1;
  let value = byte & 0x7f;
  while (byte & 0x80) {
    byte = buf[off] as number;
    off += 1;
    value = (value + 1) * 128 + (byte & 0x7f);
  }
  return { baseOffset: value, next: off };
}

function applyDelta(base: Buffer, delta: Buffer): Buffer {
  let off = 0;
  const readSize = (): number => {
    let value = 0;
    let shift = 0;
    for (;;) {
      const byte = delta[off] as number;
      off += 1;
      value += (byte & 0x7f) * 2 ** shift;
      shift += 7;
      if (!(byte & 0x80)) break;
    }
    return value;
  };
  const srcSize = readSize();
  const tgtSize = readSize();
  if (srcSize !== base.length) throw new Error('delta base size mismatch');
  const out = Buffer.allocUnsafe(tgtSize);
  let written = 0;
  while (off < delta.length) {
    const op = delta[off] as number;
    off += 1;
    if (op & 0x80) {
      let copyOff = 0;
      let copySize = 0;
      let shift = 0;
      for (let bit = 0; bit < 4; bit += 1) {
        if (op & (1 << bit)) {
          copyOff += (delta[off] as number) * 2 ** shift;
          off += 1;
        }
        shift += 8;
      }
      shift = 0;
      for (let bit = 4; bit < 7; bit += 1) {
        if (op & (1 << bit)) {
          copySize += (delta[off] as number) * 2 ** shift;
          off += 1;
        }
        shift += 8;
      }
      if (copySize === 0) copySize = 0x10000;
      base.copy(out, written, copyOff, copyOff + copySize);
      written += copySize;
    } else if (op !== 0) {
      const n = op & 0x7f;
      delta.copy(out, written, off, off + n);
      off += n;
      written += n;
    } else {
      throw new Error('delta opcode 0');
    }
  }
  if (written !== tgtSize) throw new Error('delta size mismatch');
  return out;
}

interface PackEntry {
  offset: number;
  typeCode: number;
  size: number;
  data: Buffer;
  baseOffset?: number;
  baseOid?: string;
}

// Read a packfile (plain, OFS_DELTA and REF_DELTA entries). Returns resolved objects.
function readPack(pack: Buffer, resolveBase?: (oid: string) => GitObj | undefined): Map<string, GitObj> {
  if (pack.length < 32 || pack.subarray(0, 4).toString('ascii') !== 'PACK') throw new Error('bad pack header');
  const version = pack.readUInt32BE(4);
  if (version !== 2 && version !== 3) throw new Error('bad pack version');
  const count = pack.readUInt32BE(8);
  const trailerStart = pack.length - 20;
  const raw: PackEntry[] = [];
  const byOffset = new Map<number, PackEntry>();
  let off = 12;
  for (let i = 0; i < count; i += 1) {
    const entryOffset = off;
    const header = readVarintSize(pack, off);
    off = header.next;
    const typeCode = (header.first >> 4) & 0x07;
    const entry: PackEntry = { offset: entryOffset, typeCode, size: header.size, data: Buffer.alloc(0) };
    if (typeCode === 6) {
      const base = readOfsBase(pack, off);
      off = base.next;
      entry.baseOffset = entryOffset - base.baseOffset;
    } else if (typeCode === 7) {
      entry.baseOid = pack.subarray(off, off + 20).toString('hex');
      off += 20;
    } else if (!CODE_TYPE[typeCode]) {
      throw new Error(`unknown pack type ${typeCode}`);
    }
    const inflated = inflateAt(pack, off, trailerStart);
    entry.data = inflated.data;
    off = inflated.next;
    raw.push(entry);
    byOffset.set(entryOffset, entry);
  }
  void byOffset;
  const objects = new Map<string, GitObj>();
  const resolvedByOid = new Map<string, PackEntry>();
  const resolving = new Set<number>();
  const resolve = (entry: PackEntry): { type: ObjType; data: Buffer; oid: string } => {
    if ((entry as unknown as { _oid?: string })._oid) {
      const cached = resolvedByOid.get((entry as unknown as { _oid: string })._oid);
      if (cached === entry) {
        return {
          type: (entry as unknown as { _type: ObjType })._type,
          data: (entry as unknown as { _data: Buffer })._data,
          oid: (entry as unknown as { _oid: string })._oid,
        };
      }
    }
    if (resolving.has(entry.offset)) throw new Error('delta cycle');
    resolving.add(entry.offset);
    let type: ObjType;
    let data: Buffer;
    if (entry.typeCode === 6) {
      const baseEntry = byOffset.get(entry.baseOffset as number);
      if (!baseEntry) throw new Error('ofs-delta base missing');
      const base = resolve(baseEntry);
      type = base.type;
      data = applyDelta(base.data, entry.data);
    } else if (entry.typeCode === 7) {
      const wanted = entry.baseOid as string;
      const baseEntry = resolvedByOid.get(wanted);
      if (baseEntry) {
        const base = resolve(baseEntry);
        type = base.type;
        data = applyDelta(base.data, entry.data);
      } else {
        const ext = resolveBase?.(wanted);
        if (!ext) throw new Error('ref-delta base missing');
        type = ext.type;
        data = applyDelta(ext.data, entry.data);
      }
    } else {
      type = CODE_TYPE[entry.typeCode] as ObjType;
      data = entry.data;
    }
    const oid = hashObject(type, data);
    (entry as unknown as { _oid: string })._oid = oid;
    (entry as unknown as { _type: ObjType })._type = type;
    (entry as unknown as { _data: Buffer })._data = data;
    resolvedByOid.set(oid, entry);
    resolving.delete(entry.offset);
    return { type, data, oid };
  };
  for (const entry of raw) {
    const r = resolve(entry);
    if (!objects.has(r.oid)) objects.set(r.oid, { type: r.type, data: r.data });
  }
  return objects;
}

// Inflate one zlib stream starting at `start`; returns its bytes and the offset
// just past the stream (from the engine's bytesWritten, via inflateSync info).
function inflateAt(buf: Buffer, start: number, end: number): { data: Buffer; next: number } {
  const view = buf.subarray(start, end);
  const result = inflateSync(view, { info: true }) as unknown as {
    buffer: Buffer;
    engine: { bytesWritten: number };
  };
  const written = result.engine.bytesWritten;
  if (!written || written <= 0) throw new Error('zlib stream consumed no bytes');
  return { data: result.buffer, next: start + written };
}

// ---------------------------------------------------------------- store

interface Issue {
  id: number;
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  labels: string[];
  comments: Array<{ id: number; body: string }>;
  seq: number;
  version: number;
}

interface PullFile {
  filename: string;
  status: string;
  additions: number;
  deletions: number;
  changes: number;
}

interface Pull {
  id: number;
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  headRef: string;
  baseRef: string;
  headSha: string;
  baseSha: string;
  mergeBaseSha: string;
  merged: boolean;
  mergedAt: string | null;
  mergeCommitSha: string | null;
  files: PullFile[];
  seq: number;
}

interface Repo {
  id: number;
  name: string;
  owner: string;
  private: boolean;
  description: string;
  defaultBranch: string;
  objects: Map<string, GitObj>;
  refs: Map<string, string>;
  refsVersion: number;
  labels: Map<string, { name: string; color: string }>;
  issues: Map<number, Issue>;
  nextIssue: number;
  pulls: Map<number, Pull>;
  nextPull: number;
}

const repos = new Map<string, Repo>();
const DEFAULT_LABELS: Array<[string, string]> = [
  ['bug', 'd73a4a'],
  ['enhancement', 'a2eeef'],
  ['documentation', '0075ca'],
  ['question', 'd876e3'],
  ['good first issue', '7057ff'],
  ['help wanted', '008672'],
];

function repoKey(owner: string, name: string): string {
  return `${owner}/${name}`;
}

function getRepo(owner: string, name: string): Repo | undefined {
  return repos.get(repoKey(owner, name));
}

function createRepo(owner: string, name: string, isPrivate: boolean, description: string): Repo {
  const repo: Repo = {
    id: nextRepoId,
    name,
    owner,
    private: isPrivate,
    description,
    defaultBranch: DEFAULT_BRANCH,
    objects: new Map(),
    refs: new Map(),
    refsVersion: 0,
    labels: new Map(DEFAULT_LABELS.map(([n, c]) => [n, { name: n, color: c }])),
    issues: new Map(),
    nextIssue: 1,
    pulls: new Map(),
    nextPull: 1,
  };
  nextRepoId += 1;
  repos.set(repoKey(owner, name), repo);
  return repo;
}

function deleteRepo(owner: string, name: string): boolean {
  return repos.delete(repoKey(owner, name));
}

function refTip(repo: Repo, ref: string): string | undefined {
  return repo.refs.get(ref);
}

function branchTip(repo: Repo, branch: string): string | undefined {
  return repo.refs.get(`refs/heads/${branch}`);
}

function bumpRefs(repo: Repo): void {
  repo.refsVersion += 1;
}

function storeObject(repo: Repo, type: ObjType, data: Buffer): string {
  const oid = hashObject(type, data);
  if (!repo.objects.has(oid)) repo.objects.set(oid, { type, data });
  return oid;
}

// ---------------------------------------------------------------- trees

// Look up one path (segments) in the tree at `treeOid`. Returns the blob oid
// and mode, or null when absent.
function lookupPath(repo: Repo, treeOid: string, segments: string[]): { oid: string; mode: string } | null {
  let cur = treeOid;
  for (let i = 0; i < segments.length; i += 1) {
    const obj = repo.objects.get(cur);
    if (!obj || obj.type !== 'tree') return null;
    const entry = parseTree(obj.data).find((e) => e.name === segments[i]);
    if (!entry) return null;
    if (i === segments.length - 1) return { oid: entry.oid, mode: entry.mode };
    if (entry.mode !== '40000') return null;
    cur = entry.oid;
  }
  return null;
}

// The tree oid at `ref` (branch name or full ref or commit oid), or null.
function treeAtRef(repo: Repo, ref: string): string | null {
  let oid: string | undefined;
  if (ref.startsWith('refs/')) oid = repo.refs.get(ref);
  else if (isOid(ref)) oid = ref;
  else oid = repo.refs.get(`refs/heads/${ref}`);
  if (!oid) return null;
  const obj = repo.objects.get(oid);
  if (!obj) return null;
  if (obj.type === 'commit') return parseCommit(obj.data).tree;
  if (obj.type === 'tag') {
    const peeled = peelToCommit(repo, oid);
    if (!peeled) return null;
    const commit = repo.objects.get(peeled);
    if (!commit) return null;
    return parseCommit(commit.data).tree;
  }
  return null;
}

// Rebuild the tree at `treeOid` with `segments` set to `blobOid` (or removed
// when null). Returns the new tree oid, storing new tree objects.
function updateTree(repo: Repo, treeOid: string | null, segments: string[], blobOid: string | null): string {
  if (segments.length === 0) return treeOid ?? storeObject(repo, 'tree', buildTree([]));
  const [head, ...rest] = segments as [string, ...string[]];
  const obj = treeOid ? repo.objects.get(treeOid) : undefined;
  const entries = obj && obj.type === 'tree' ? parseTree(obj.data) : [];
  const idx = entries.findIndex((e) => e.name === head);
  if (rest.length === 0) {
    if (blobOid === null) {
      if (idx >= 0) entries.splice(idx, 1);
    } else if (idx >= 0) {
      entries[idx] = { mode: '100644', name: head, oid: blobOid };
    } else {
      entries.push({ mode: '100644', name: head, oid: blobOid });
    }
    return storeObject(repo, 'tree', buildTree(entries));
  }
  const childTree = idx >= 0 && entries[idx]?.mode === '40000' ? (entries[idx] as TreeEntry).oid : null;
  const newChild = updateTree(repo, childTree, rest, blobOid);
  // If the child tree is now empty and we removed something, drop the dir.
  const childObj = repo.objects.get(newChild);
  const childEmpty = childObj !== undefined && childObj.type === 'tree' && parseTree(childObj.data).length === 0;
  if (blobOid === null && childEmpty) {
    if (idx >= 0) entries.splice(idx, 1);
  } else if (idx >= 0) {
    entries[idx] = { mode: '40000', name: head, oid: newChild };
  } else {
    entries.push({ mode: '40000', name: head, oid: newChild });
  }
  return storeObject(repo, 'tree', buildTree(entries));
}

// List every file (path -> blob oid) under the tree at `treeOid`.
function flattenTree(repo: Repo, treeOid: string, prefix = ''): Map<string, string> {
  const out = new Map<string, string>();
  const obj = repo.objects.get(treeOid);
  if (!obj || obj.type !== 'tree') return out;
  for (const e of parseTree(obj.data)) {
    const path = prefix === '' ? e.name : `${prefix}/${e.name}`;
    if (e.mode === '40000') {
      for (const [k, v] of flattenTree(repo, e.oid, path)) out.set(k, v);
    } else {
      out.set(path, e.oid);
    }
  }
  return out;
}

// All commits reachable from `tip`, newest first (by creation sequence).
// We track creation order per commit in `commitSeq`.
const commitSeq = new Map<string, number>();
let commitSeqCounter = 0;

function listCommits(repo: Repo, tip: string): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  const queue = [tip];
  while (queue.length) {
    const oid = queue.pop() as string;
    if (seen.has(oid)) continue;
    seen.add(oid);
    const obj = repo.objects.get(oid);
    if (!obj || obj.type !== 'commit') continue;
    out.push(oid);
    for (const p of parseCommit(obj.data).parents) queue.push(p);
  }
  out.sort((a, b) => (commitSeq.get(b) ?? 0) - (commitSeq.get(a) ?? 0));
  return out;
}

// Create a commit on `branch` (default branch when undefined) applying file
// writes (content null deletes). Returns the new commit oid.
function commitFiles(
  repo: Repo,
  branch: string | undefined,
  writes: Array<{ path: string; content: Buffer | null }>,
  message: string,
): string {
  const target = branch ?? repo.defaultBranch;
  const ref = `refs/heads/${target}`;
  const parent = repo.refs.get(ref);
  let treeOid: string | null = null;
  if (parent) {
    const obj = repo.objects.get(parent);
    if (obj && obj.type === 'commit') treeOid = parseCommit(obj.data).tree;
  }
  for (const w of writes) {
    const segments = w.path.split('/').filter((s) => s !== '');
    let blobOid: string | null = null;
    if (w.content !== null) blobOid = storeObject(repo, 'blob', w.content);
    treeOid = updateTree(repo, treeOid, segments, blobOid);
  }
  const ts = FIXED_COMMIT_TS + nextSeq();
  const commit = buildCommit(treeOid ?? storeObject(repo, 'tree', buildTree([])), parent ? [parent] : [], message, ts);
  const commitOid = storeObject(repo, 'commit', commit);
  commitSeqCounter += 1;
  commitSeq.set(commitOid, commitSeqCounter);
  repo.refs.set(ref, commitOid);
  bumpRefs(repo);
  return commitOid;
}

// Diff base tree vs head tree: files added / modified / removed.
function diffTrees(repo: Repo, baseTree: string | null, headTree: string | null): PullFile[] {
  const base = baseTree ? flattenTree(repo, baseTree) : new Map<string, string>();
  const head = headTree ? flattenTree(repo, headTree) : new Map<string, string>();
  const files: PullFile[] = [];
  const countLines = (oid: string): number => {
    const obj = repo.objects.get(oid);
    if (!obj) return 0;
    const text = obj.data.toString('utf8');
    if (text === '') return 0;
    return text.split('\n').length - (text.endsWith('\n') ? 1 : 0) + (text.endsWith('\n') ? 0 : 0) + (text === '' ? 0 : 0);
  };
  const lineCount = (oid: string): number => {
    const obj = repo.objects.get(oid);
    if (!obj) return 0;
    const text = obj.data.toString('utf8');
    if (text.length === 0) return 0;
    let n = 0;
    for (let i = 0; i < text.length; i += 1) if (text[i] === '\n') n += 1;
    return text.endsWith('\n') ? n : n + 1;
  };
  void countLines;
  for (const [path, oid] of head) {
    const old = base.get(path);
    if (old === undefined) {
      const adds = lineCount(oid);
      files.push({ filename: path, status: 'added', additions: Math.max(1, adds), deletions: 0, changes: Math.max(1, adds) });
    } else if (old !== oid) {
      const adds = lineCount(oid);
      const dels = lineCount(old);
      files.push({ filename: path, status: 'modified', additions: Math.max(1, adds), deletions: dels, changes: Math.max(1, adds) + dels });
    }
  }
  for (const [path] of base) {
    if (!head.has(path)) {
      const dels = lineCount(base.get(path) as string);
      files.push({ filename: path, status: 'removed', additions: 0, deletions: dels, changes: dels });
    }
  }
  files.sort((a, b) => (a.filename < b.filename ? -1 : 1));
  return files;
}

// Would merging `pull` conflict with the current base tip? A file the head
// changed against the merge base conflicts when the base tip also changed it
// to something different from the head version.
function pullConflicts(repo: Repo, pull: Pull): boolean {
  const baseTip = branchTip(repo, pull.baseRef);
  if (!baseTip) return false;
  const baseTree = treeAtRef(repo, pull.baseRef);
  const mergeBaseTree = treeAtRef(repo, pull.mergeBaseSha);
  const headTree = treeAtRef(repo, pull.headSha);
  if (baseTree === null || mergeBaseTree === null || headTree === null) return false;
  const baseFiles = flattenTree(repo, baseTree);
  const mergeFiles = flattenTree(repo, mergeBaseTree);
  const headFiles = flattenTree(repo, headTree);
  for (const file of pull.files) {
    const path = file.filename;
    const mergeV = mergeFiles.get(path);
    const headV = headFiles.get(path);
    const baseV = baseFiles.get(path);
    if (headV === mergeV) continue; // head did not change this file
    if (baseV === mergeV) continue; // base did not change this file
    if (baseV === headV) continue; // both changed it to the same thing
    return true;
  }
  return false;
}

// Squash-merge an open pull request onto its base branch. Returns the merge
// commit oid, or null when conflicted.
function mergePullRequest(repo: Repo, pull: Pull): string | null {
  if (pull.state !== 'open' || pull.merged) return null;
  if (pullConflicts(repo, pull)) return null;
  const baseTip = branchTip(repo, pull.baseRef);
  if (!baseTip) return null;
  const headTree = treeAtRef(repo, pull.headSha);
  if (headTree === null) return null;
  const ts = FIXED_COMMIT_TS + nextSeq();
  const message = `Merge pull request #${pull.number} from ${pull.headRef}\n\n${pull.title}\n`;
  const commit = buildCommit(headTree, [baseTip], message, ts);
  const mergeOid = storeObject(repo, 'commit', commit);
  commitSeqCounter += 1;
  commitSeq.set(mergeOid, commitSeqCounter);
  repo.refs.set(`refs/heads/${pull.baseRef}`, mergeOid);
  bumpRefs(repo);
  pull.state = 'closed';
  pull.merged = true;
  pull.mergedAt = isoTs(nextSeq());
  pull.mergeCommitSha = mergeOid;
  return mergeOid;
}

// ---------------------------------------------------------------- http core

interface Ctx {
  req: http.IncomingMessage;
  res: http.ServerResponse;
  method: string;
  path: string;
  query: URLSearchParams | null;
  segments: string[];
}

function queryOf(ctx: Ctx): URLSearchParams {
  if (ctx.query === null) {
    const q = ctx.req.url?.indexOf('?') ?? -1;
    ctx.query = new URLSearchParams(q >= 0 ? (ctx.req.url as string).slice(q + 1) : '');
  }
  return ctx.query;
}

function sendRaw(ctx: Ctx, status: number, body: Buffer, contentType: string, extra?: Record<string, string>): void {
  const headers: Record<string, string> = {
    'content-type': contentType,
    'x-github-request-id': requestId(),
    ...extra,
  };
  ctx.res.writeHead(status, headers);
  ctx.res.end(body);
}

function sendJson(ctx: Ctx, status: number, value: unknown, extra?: Record<string, string>): void {
  sendRaw(ctx, status, Buffer.from(JSON.stringify(value), 'utf8'), 'application/json', extra);
}

function sendErr(ctx: Ctx, status: number, message: string): void {
  sendJson(ctx, status, { message });
}

function readBody(req: http.IncomingMessage, maxBytes = 128 * 1024 * 1024): Promise<Buffer> {
  return new Promise<Buffer>((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    req.on('data', (chunk: Buffer) => {
      total += chunk.length;
      if (total > maxBytes) {
        reject(new Error('body too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks, total)));
    req.on('error', reject);
  });
}

function parseJsonBody(buf: Buffer): unknown {
  if (buf.length === 0) return {};
  return JSON.parse(buf.toString('utf8'));
}

function authed(ctx: Ctx): boolean {
  const h = ctx.req.headers.authorization;
  return h === `Bearer ${TOKEN}`;
}

// ---------------------------------------------------------------- caches

// Advertisement bytes per repo/service/refsVersion.
const advCache = new Map<string, Buffer>();
// Full fetch-response bytes per fetch key (v2), and pack bytes per object set.
const fetchCache = new Map<string, Buffer>();
const packCache = new Map<string, Buffer>();
// Cached single-issue JSON bytes, invalidated by bumping the issue version.
const issueCache = new Map<string, { version: number; body: Buffer }>();

function repoJson(repo: Repo): Record<string, unknown> {
  return {
    id: repo.id,
    node_id: gid('Repository', repo.id),
    name: repo.name,
    full_name: `${repo.owner}/${repo.name}`,
    owner: { login: repo.owner, id: repo.owner === VIEWER_LOGIN ? VIEWER_ID : 0, type: 'User' },
    private: repo.private,
    description: repo.description,
    default_branch: repo.defaultBranch,
    created_at: isoTs(repo.id),
    updated_at: isoTs(repo.id),
    pushed_at: isoTs(repo.id),
    html_url: `https://github.com/${repo.owner}/${repo.name}`,
    url: `/repos/${repo.owner}/${repo.name}`,
    clone_url: `https://github.com/${repo.owner}/${repo.name}.git`,
    git_url: `git://github.com/${repo.owner}/${repo.name}.git`,
    ssh_url: `git@github.com:${repo.owner}/${repo.name}.git`,
    homepage: null,
    language: null,
    forks_count: 0,
    stargazers_count: 0,
    watchers_count: 0,
    open_issues_count: [...repo.issues.values()].filter((i) => i.state === 'open').length,
    has_issues: true,
    has_projects: true,
    has_wiki: true,
    has_pages: false,
    archived: false,
    disabled: false,
    visibility: repo.private ? 'private' : 'public',
    license: null,
  };
}

function labelJson(label: { name: string; color: string }): Record<string, unknown> {
  return { id: 0, node_id: gid('Label', 1), name: label.name, color: label.color, description: '', default: false };
}

function issueJson(repo: Repo, issue: Issue): Record<string, unknown> {
  return {
    id: issue.id,
    node_id: gid('Issue', issue.id),
    number: issue.number,
    title: issue.title,
    body: issue.body,
    state: issue.state,
    locked: false,
    labels: issue.labels.map((n) => {
      const l = repo.labels.get(n);
      return { name: n, color: l ? l.color : 'ededed', description: '' };
    }),
    user: { login: VIEWER_LOGIN, id: VIEWER_ID, type: 'User' },
    assignee: null,
    assignees: [],
    milestone: null,
    comments: issue.comments.length,
    created_at: isoTs(issue.seq),
    updated_at: isoTs(issue.seq),
    closed_at: issue.state === 'closed' ? isoTs(issue.seq) : null,
    author_association: 'OWNER',
    html_url: `https://github.com/${repo.owner}/${repo.name}/issues/${issue.number}`,
    url: `/repos/${repo.owner}/${repo.name}/issues/${issue.number}`,
  };
}

function issueBytes(repo: Repo, issue: Issue): Buffer {
  const key = `${repo.owner}/${repo.name}/${issue.number}`;
  const cached = issueCache.get(key);
  if (cached && cached.version === issue.version) return cached.body;
  const body = Buffer.from(JSON.stringify(issueJson(repo, issue)), 'utf8');
  issueCache.set(key, { version: issue.version, body });
  return body;
}

function commentJson(repo: Repo, issue: Issue, comment: { id: number; body: string }): Record<string, unknown> {
  return {
    id: comment.id,
    node_id: gid('IssueComment', comment.id),
    body: comment.body,
    user: { login: VIEWER_LOGIN, id: VIEWER_ID, type: 'User' },
    created_at: isoTs(issue.seq),
    updated_at: isoTs(issue.seq),
    html_url: `https://github.com/${repo.owner}/${repo.name}/issues/${issue.number}#issuecomment-${comment.id}`,
    url: `/repos/${repo.owner}/${repo.name}/issues/comments/${comment.id}`,
  };
}

function pullJson(repo: Repo, pull: Pull): Record<string, unknown> {
  const headSha = branchTip(repo, pull.headRef) ?? pull.headSha;
  const baseSha = branchTip(repo, pull.baseRef) ?? pull.baseSha;
  return {
    id: pull.id,
    node_id: gid('PullRequest', pull.id),
    number: pull.number,
    title: pull.title,
    body: pull.body,
    state: pull.state,
    locked: false,
    draft: false,
    merged: pull.merged,
    mergeable: pull.state === 'open' ? !pullConflicts(repo, pull) : null,
    mergeable_state: pull.state === 'open' ? (pullConflicts(repo, pull) ? 'dirty' : 'clean') : 'unknown',
    merged_at: pull.mergedAt,
    merge_commit_sha: pull.mergeCommitSha,
    closed_at: pull.state === 'closed' ? pull.mergedAt ?? isoTs(pull.seq) : null,
    created_at: isoTs(pull.seq),
    updated_at: isoTs(pull.seq),
    head: { ref: pull.headRef, sha: headSha, label: `${repo.owner}:${pull.headRef}`, user: { login: repo.owner, id: VIEWER_ID } },
    base: { ref: pull.baseRef, sha: baseSha, label: `${repo.owner}:${pull.baseRef}`, user: { login: repo.owner, id: VIEWER_ID } },
    user: { login: VIEWER_LOGIN, id: VIEWER_ID, type: 'User' },
    assignee: null,
    assignees: [],
    requested_reviewers: [],
    labels: [],
    milestone: null,
    html_url: `https://github.com/${repo.owner}/${repo.name}/pull/${pull.number}`,
    url: `/repos/${repo.owner}/${repo.name}/pulls/${pull.number}`,
  };
}

function commitJson(repo: Repo, oid: string): Record<string, unknown> | null {
  const obj = repo.objects.get(oid);
  if (!obj || obj.type !== 'commit') return null;
  const c = parseCommit(obj.data);
  const seq = commitSeq.get(oid) ?? 0;
  const who = { name: VIEWER_NAME, email: VIEWER_EMAIL, date: isoTs(seq) };
  return {
    sha: oid,
    node_id: gid('Commit', 1),
    commit: {
      message: c.message,
      author: who,
      committer: who,
      tree: { sha: c.tree },
      url: `/repos/${repo.owner}/${repo.name}/git/commits/${oid}`,
    },
    author: { login: VIEWER_LOGIN, id: VIEWER_ID, type: 'User' },
    committer: { login: VIEWER_LOGIN, id: VIEWER_ID, type: 'User' },
    parents: c.parents.map((p) => ({ sha: p })),
    url: `/repos/${repo.owner}/${repo.name}/commits/${oid}`,
    html_url: `https://github.com/${repo.owner}/${repo.name}/commit/${oid}`,
  };
}

// ---------------------------------------------------------------- rest: helpers

function decodeSeg(s: string): string {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}

function ownerRepo(ctx: Ctx): { owner: string; name: string } | null {
  // segments: ['repos', owner, name, ...]
  if (ctx.segments.length < 3) return null;
  return { owner: decodeSeg(ctx.segments[1] as string), name: decodeSeg(ctx.segments[2] as string) };
}

function loadRepo(ctx: Ctx): Repo | null {
  const or = ownerRepo(ctx);
  if (!or) return null;
  const repo = getRepo(or.owner, or.name);
  if (!repo) return null;
  return repo;
}

function paginate<T>(items: T[], ctx: Ctx): { page: T[]; link: string | null } {
  const q = queryOf(ctx);
  const perPageRaw = Number(q.get('per_page') ?? '30');
  const perPage = Number.isFinite(perPageRaw) && perPageRaw > 0 ? Math.min(100, Math.trunc(perPageRaw)) : 30;
  const pageRaw = Number(q.get('page') ?? '1');
  const page = Number.isFinite(pageRaw) && pageRaw > 0 ? Math.trunc(pageRaw) : 1;
  const start = (page - 1) * perPage;
  const slice = items.slice(start, start + perPage);
  let link: string | null = null;
  if (start + perPage < items.length || page > 1) {
    const host = ctx.req.headers.host ?? '127.0.0.1';
    const base = `http://${host}${ctx.path}`;
    const parts: string[] = [];
    const q2 = new URLSearchParams(queryOf(ctx).toString());
    if (start + perPage < items.length) {
      q2.set('page', String(page + 1));
      q2.set('per_page', String(perPage));
      parts.push(`<${base}?${q2.toString()}>; rel="next"`);
      q2.set('page', String(Math.ceil(items.length / perPage)));
      parts.push(`<${base}?${q2.toString()}>; rel="last"`);
    }
    if (page > 1) {
      q2.set('page', '1');
      q2.set('per_page', String(perPage));
      parts.push(`<${base}?${q2.toString()}>; rel="first"`);
      q2.set('page', String(page - 1));
      parts.push(`<${base}?${q2.toString()}>; rel="prev"`);
    }
    link = parts.join(', ');
  }
  return { page: slice, link };
}

// ---------------------------------------------------------------- rest router

async function handleRest(ctx: Ctx, body: Buffer): Promise<void> {
  const seg = ctx.segments.slice(2); // after 'api','v3'
  const method = ctx.method;

  // GET /api/v3/ — the API root.
  if (seg.length === 0) {
    if (method !== 'GET') return sendErr(ctx, 404, 'Not Found');
    return sendJson(
      ctx,
      200,
      {
        current_user_url: '/api/v3/user',
        repository_url: '/api/v3/repos/{owner}/{repo}',
        user_url: '/api/v3/users/{user}',
        rate_limit_url: '/api/v3/rate_limit',
        meta: { verifiable_password_authentication: true },
      },
      { 'x-oauth-scopes': 'repo, read:org' },
    );
  }

  // GET /api/v3/meta
  if (seg.length === 1 && seg[0] === 'meta') {
    if (method !== 'GET') return sendErr(ctx, 404, 'Not Found');
    return sendJson(ctx, 200, { installed_version: VERSION });
  }

  // GET /api/v3/user
  if (seg.length === 1 && seg[0] === 'user' && method === 'GET') {
    return sendJson(ctx, 200, {
      login: VIEWER_LOGIN,
      id: VIEWER_ID,
      node_id: gid('User', VIEWER_ID),
      name: VIEWER_NAME,
      email: VIEWER_EMAIL,
      type: 'User',
      site_admin: false,
    });
  }

  // /api/v3/user/repos
  if (seg.length === 2 && seg[0] === 'user' && seg[1] === 'repos') {
    if (method === 'GET') {
      const mine = [...repos.values()].filter((r) => r.owner === VIEWER_LOGIN).sort((a, b) => a.id - b.id);
      const { page, link } = paginate(mine.map((r) => repoJson(r)), ctx);
      return sendJson(ctx, 200, page, link ? { link } : undefined);
    }
    if (method === 'POST') {
      let input: Record<string, unknown>;
      try {
        input = parseJsonBody(body) as Record<string, unknown>;
      } catch {
        return sendErr(ctx, 400, 'Problems parsing JSON');
      }
      const name = typeof input.name === 'string' ? input.name.trim() : '';
      if (name === '' || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/.test(name)) {
        return sendErr(ctx, 422, 'Validation Failed: name is invalid');
      }
      if (getRepo(VIEWER_LOGIN, name)) {
        return sendErr(ctx, 422, `Repository ${VIEWER_LOGIN}/${name} already exists`);
      }
      const repo = createRepo(
        VIEWER_LOGIN,
        name,
        input.private === true,
        typeof input.description === 'string' ? input.description : '',
      );
      return sendJson(ctx, 201, repoJson(repo));
    }
    return sendErr(ctx, 404, 'Not Found');
  }

  // /api/v3/repos/{owner}/{repo}[...]
  if (seg.length >= 3 && seg[0] === 'repos') {
    return handleRepoRoutes(ctx, seg, body);
  }

  return sendErr(ctx, 404, 'Not Found');
}

async function handleRepoRoutes(ctx: Ctx, seg: string[], body: Buffer): Promise<void> {
  const method = ctx.method;
  const owner = decodeSeg(seg[1] as string);
  const name = decodeSeg(seg[2] as string);
  const rest = seg.slice(3);
  const repo = getRepo(owner, name);
  if (!repo) return sendErr(ctx, 404, 'Not Found');

  // The repository itself.
  if (rest.length === 0) {
    if (method === 'GET') return sendJson(ctx, 200, repoJson(repo));
    if (method === 'PATCH') {
      let input: Record<string, unknown>;
      try {
        input = parseJsonBody(body) as Record<string, unknown>;
      } catch {
        return sendErr(ctx, 400, 'Problems parsing JSON');
      }
      if (typeof input.description === 'string') repo.description = input.description;
      if (typeof input.private === 'boolean') repo.private = input.private;
      return sendJson(ctx, 200, repoJson(repo));
    }
    if (method === 'DELETE') {
      deleteRepo(owner, name);
      return sendRaw(ctx, 204, Buffer.alloc(0), 'application/json');
    }
    return sendErr(ctx, 404, 'Not Found');
  }

  const head = rest[0] as string;

  // Branches.
  if (head === 'branches') {
    if (rest.length === 1 && method === 'GET') {
      const list = [...repo.refs.entries()]
        .filter(([ref]) => ref.startsWith('refs/heads/'))
        .map(([ref, sha]) => ({ name: ref.slice('refs/heads/'.length), commit: { sha }, protected: false }))
        .sort((a, b) => (a.name < b.name ? -1 : 1));
      return sendJson(ctx, 200, list);
    }
    if (rest.length >= 2 && method === 'GET') {
      const branch = rest.slice(1).map(decodeSeg).join('/');
      const tip = branchTip(repo, branch);
      if (!tip) return sendErr(ctx, 404, 'Branch not found');
      return sendJson(ctx, 200, { name: branch, commit: { sha: tip }, protected: false });
    }
    return sendErr(ctx, 404, 'Not Found');
  }

  // Commits.
  if (head === 'commits' && method === 'GET' && rest.length === 1) {
    const q = queryOf(ctx);
    const ref = q.get('sha') ?? repo.defaultBranch;
    const treeTip = treeAtRef(repo, ref);
    if (treeTip === null && !branchTip(repo, ref) && !isOid(ref)) return sendErr(ctx, 404, 'Not Found');
    let tip: string | undefined;
    if (ref.startsWith('refs/')) tip = repo.refs.get(ref);
    else if (isOid(ref)) tip = ref;
    else tip = branchTip(repo, ref);
    if (!tip) return sendJson(ctx, 200, []);
    const commits = listCommits(repo, tip)
      .map((oid) => commitJson(repo, oid))
      .filter((c): c is Record<string, unknown> => c !== null);
    const { page } = paginate(commits, ctx);
    return sendJson(ctx, 200, page);
  }

  // Git data: refs.
  if (head === 'git' && rest[1] === 'refs') {
    if (method === 'POST' && rest.length === 2) {
      let input: Record<string, unknown>;
      try {
        input = parseJsonBody(body) as Record<string, unknown>;
      } catch {
        return sendErr(ctx, 400, 'Problems parsing JSON');
      }
      const ref = typeof input.ref === 'string' ? input.ref : '';
      const sha = typeof input.sha === 'string' ? input.sha : '';
      if (!ref.startsWith('refs/') || !isOid(sha)) return sendErr(ctx, 422, 'Validation Failed');
      const obj = repo.objects.get(sha);
      if (!obj || obj.type !== 'commit') return sendErr(ctx, 422, 'Validation Failed: sha is not a commit');
      if (repo.refs.has(ref)) return sendErr(ctx, 422, 'Reference already exists');
      repo.refs.set(ref, sha);
      bumpRefs(repo);
      return sendJson(ctx, 201, { ref, node_id: gid('Ref', 1), object: { sha, type: 'commit' }, url: `/repos/${owner}/${name}/git/refs/${ref}` });
    }
    if (method === 'GET' && rest.length >= 3) {
      const refName = rest.slice(2).map(decodeSeg).join('/');
      const tip = repo.refs.get(refName);
      if (!tip) return sendErr(ctx, 404, 'Not Found');
      return sendJson(ctx, 200, { ref: refName, node_id: gid('Ref', 1), object: { sha: tip, type: 'commit' }, url: `/repos/${owner}/${name}/git/refs/${refName}` });
    }
    return sendErr(ctx, 404, 'Not Found');
  }

  // Contents.
  if (head === 'contents') {
    return handleContents(ctx, repo, rest.slice(1), body);
  }

  // Labels.
  if (head === 'labels') {
    if (method === 'GET' && rest.length === 1) {
      return sendJson(ctx, 200, [...repo.labels.values()].map(labelJson));
    }
    if (method === 'POST' && rest.length === 1) {
      let input: Record<string, unknown>;
      try {
        input = parseJsonBody(body) as Record<string, unknown>;
      } catch {
        return sendErr(ctx, 400, 'Problems parsing JSON');
      }
      const labelName = typeof input.name === 'string' ? input.name : '';
      if (labelName === '') return sendErr(ctx, 422, 'Validation Failed: name is required');
      const color = typeof input.color === 'string' ? input.color : 'ededed';
      const existing = repo.labels.get(labelName);
      if (existing) return sendJson(ctx, 201, labelJson(existing));
      const label = { name: labelName, color };
      repo.labels.set(labelName, label);
      return sendJson(ctx, 201, labelJson(label));
    }
    return sendErr(ctx, 404, 'Not Found');
  }

  // Issues.
  if (head === 'issues') {
    return handleIssues(ctx, repo, rest.slice(1), body);
  }

  // Pull requests.
  if (head === 'pulls') {
    return handlePulls(ctx, repo, rest.slice(1), body);
  }

  return sendErr(ctx, 404, 'Not Found');
}

// ---------------------------------------------------------------- contents

async function handleContents(ctx: Ctx, repo: Repo, rest: string[], body: Buffer): Promise<void> {
  const method = ctx.method;
  const path = rest.map(decodeSeg).join('/');
  const q = queryOf(ctx);
  const ref = q.get('ref') ?? undefined;

  if (method === 'GET') {
    if (path === '') return sendErr(ctx, 404, 'Not Found');
    const treeOid = treeAtRef(repo, ref ?? repo.defaultBranch);
    if (treeOid === null) return sendErr(ctx, 404, 'Not Found');
    const segments = path.split('/').filter((s) => s !== '');
    const found = lookupPath(repo, treeOid, segments);
    if (found) {
      if (found.mode === '40000') {
        const entries = dirEntries(repo, found.oid, path);
        return sendJson(ctx, 200, entries);
      }
      const obj = repo.objects.get(found.oid);
      if (!obj) return sendErr(ctx, 404, 'Not Found');
      return sendJson(ctx, 200, {
        type: 'file',
        encoding: 'base64',
        size: obj.data.length,
        name: segments[segments.length - 1] as string,
        path,
        content: b64encode(obj.data),
        sha: found.oid,
        url: `/repos/${repo.owner}/${repo.name}/contents/${path}`,
        html_url: `https://github.com/${repo.owner}/${repo.name}/blob/${ref ?? repo.defaultBranch}/${path}`,
        git_url: `/repos/${repo.owner}/${repo.name}/git/blobs/${found.oid}`,
        download_url: null,
      });
    }
    // Maybe a directory.
    const dirTree = dirTreeOid(repo, treeOid, segments);
    if (dirTree !== null) {
      return sendJson(ctx, 200, dirEntries(repo, dirTree, path));
    }
    return sendErr(ctx, 404, 'Not Found');
  }

  if (method === 'PUT') {
    let input: Record<string, unknown>;
    try {
      input = parseJsonBody(body) as Record<string, unknown>;
    } catch {
      return sendErr(ctx, 400, 'Problems parsing JSON');
    }
    const message = typeof input.message === 'string' ? input.message : 'update';
    const contentB64 = typeof input.content === 'string' ? input.content : '';
    const branch = typeof input.branch === 'string' ? input.branch : undefined;
    const sha = typeof input.sha === 'string' ? input.sha : undefined;
    const segments = path.split('/').filter((s) => s !== '');
    if (segments.length === 0 || contentB64 === '') return sendErr(ctx, 422, 'Validation Failed');
    const targetBranch = branch ?? repo.defaultBranch;
    const currentTree = treeAtRef(repo, targetBranch);
    const current = currentTree ? lookupPath(repo, currentTree, segments) : null;
    const isUpdate = current !== null && current.mode !== '40000';
    if (isUpdate && sha !== undefined && sha.toLowerCase() !== current.oid.toLowerCase()) {
      return sendErr(ctx, 409, 'Conflict: sha does not match the current blob');
    }
    const content = b64decode(contentB64);
    const commitOid = commitFiles(repo, targetBranch, [{ path, content }], message);
    const newTree = treeAtRef(repo, targetBranch) as string;
    const after = lookupPath(repo, newTree, segments);
    const blobSha = after ? after.oid : hashObject('blob', content);
    return sendJson(ctx, isUpdate ? 200 : 201, {
      content: {
        name: segments[segments.length - 1] as string,
        path,
        sha: blobSha,
        size: content.length,
        type: 'file',
        encoding: 'base64',
        content: contentB64,
        url: `/repos/${repo.owner}/${repo.name}/contents/${path}`,
      },
      commit: { sha: commitOid, message },
    });
  }

  if (method === 'DELETE') {
    let input: Record<string, unknown> = {};
    if (body.length > 0) {
      try {
        input = parseJsonBody(body) as Record<string, unknown>;
      } catch {
        return sendErr(ctx, 400, 'Problems parsing JSON');
      }
    }
    const message = typeof input.message === 'string' ? input.message : 'delete';
    const branch = typeof input.branch === 'string' ? input.branch : undefined;
    const targetBranch = branch ?? repo.defaultBranch;
    const segments = path.split('/').filter((s) => s !== '');
    const currentTree = treeAtRef(repo, targetBranch);
    const current = currentTree ? lookupPath(repo, currentTree, segments) : null;
    if (!current || current.mode === '40000') return sendErr(ctx, 404, 'Not Found');
    const commitOid = commitFiles(repo, targetBranch, [{ path, content: null }], message);
    return sendJson(ctx, 200, { content: null, commit: { sha: commitOid, message } });
  }

  return sendErr(ctx, 404, 'Not Found');
}

function dirTreeOid(repo: Repo, treeOid: string, segments: string[]): string | null {
  let cur = treeOid;
  for (const s of segments) {
    const obj = repo.objects.get(cur);
    if (!obj || obj.type !== 'tree') return null;
    const entry = parseTree(obj.data).find((e) => e.name === s && e.mode === '40000');
    if (!entry) return null;
    cur = entry.oid;
  }
  return cur;
}

function dirEntries(repo: Repo, treeOid: string, dirPath: string): Array<Record<string, unknown>> {
  const obj = repo.objects.get(treeOid);
  if (!obj || obj.type !== 'tree') return [];
  return parseTree(obj.data).map((e) => {
    const isDir = e.mode === '40000';
    const entryObj = repo.objects.get(e.oid);
    return {
      type: isDir ? 'dir' : 'file',
      size: isDir ? 0 : (entryObj?.data.length ?? 0),
      name: e.name,
      path: dirPath === '' ? e.name : `${dirPath}/${e.name}`,
      sha: e.oid,
      url: `/repos/${repo.owner}/${repo.name}/contents/${dirPath === '' ? e.name : `${dirPath}/${e.name}`}`,
      html_url: `https://github.com/${repo.owner}/${repo.name}/tree/${repo.defaultBranch}/${dirPath === '' ? e.name : `${dirPath}/${e.name}`}`,
      git_url: `/repos/${repo.owner}/${repo.name}/git/trees/${e.oid}`,
      download_url: isDir ? null : `/repos/${repo.owner}/${repo.name}/contents/${dirPath === '' ? e.name : `${dirPath}/${e.name}`}`,
    };
  });
}

// ---------------------------------------------------------------- issues

async function handleIssues(ctx: Ctx, repo: Repo, rest: string[], body: Buffer): Promise<void> {
  const method = ctx.method;

  // /issues — list or create.
  if (rest.length === 0) {
    if (method === 'GET') {
      const q = queryOf(ctx);
      const state = q.get('state') ?? 'open';
      const sort = q.get('sort') ?? 'created';
      const direction = q.get('direction') ?? (sort === 'created' ? 'desc' : 'desc');
      let list = [...repo.issues.values()];
      if (state === 'open') list = list.filter((i) => i.state === 'open');
      else if (state === 'closed') list = list.filter((i) => i.state === 'closed');
      list.sort((a, b) => (direction === 'asc' ? a.seq - b.seq : b.seq - a.seq));
      const { page, link } = paginate(list.map((i) => issueJson(repo, i)), ctx);
      return sendJson(ctx, 200, page, link ? { link } : undefined);
    }
    if (method === 'POST') {
      let input: Record<string, unknown>;
      try {
        input = parseJsonBody(body) as Record<string, unknown>;
      } catch {
        return sendErr(ctx, 400, 'Problems parsing JSON');
      }
      const title = typeof input.title === 'string' ? input.title : '';
      if (title === '') return sendErr(ctx, 422, 'Validation Failed: title is required');
      const labelsRaw = Array.isArray(input.labels) ? (input.labels as unknown[]) : [];
      const labels: string[] = [];
      for (const l of labelsRaw) {
        if (typeof l === 'string') {
          if (!repo.labels.has(l)) return sendErr(ctx, 422, `Validation Failed: label "${l}" does not exist`);
          labels.push(l);
        } else if (l !== null && typeof l === 'object' && typeof (l as Record<string, unknown>).name === 'string') {
          const n = (l as Record<string, unknown>).name as string;
          if (!repo.labels.has(n)) return sendErr(ctx, 422, `Validation Failed: label "${n}" does not exist`);
          labels.push(n);
        }
      }
      const seq = nextSeq();
      const issue: Issue = {
        id: nextIssueId,
        number: repo.nextIssue,
        title,
        body: typeof input.body === 'string' ? input.body : '',
        state: 'open',
        labels,
        comments: [],
        seq,
        version: 1,
      };
      nextIssueId += 1;
      repo.nextIssue += 1;
      repo.issues.set(issue.number, issue);
      return sendJson(ctx, 201, issueJson(repo, issue));
    }
    return sendErr(ctx, 404, 'Not Found');
  }

  const num = Number(rest[0]);
  if (!Number.isInteger(num) || num <= 0) return sendErr(ctx, 404, 'Not Found');
  const issue = repo.issues.get(num);
  if (!issue) return sendErr(ctx, 404, 'Not Found');

  // /issues/{n}
  if (rest.length === 1) {
    if (method === 'GET') {
      return sendRaw(ctx, 200, issueBytes(repo, issue), 'application/json');
    }
    if (method === 'PATCH') {
      let input: Record<string, unknown>;
      try {
        input = parseJsonBody(body) as Record<string, unknown>;
      } catch {
        return sendErr(ctx, 400, 'Problems parsing JSON');
      }
      if (input.state === 'open' || input.state === 'closed') issue.state = input.state;
      if (typeof input.title === 'string') issue.title = input.title;
      if (typeof input.body === 'string') issue.body = input.body;
      if (Array.isArray(input.labels)) {
        const labels: string[] = [];
        for (const l of input.labels as unknown[]) {
          if (typeof l === 'string' && repo.labels.has(l)) labels.push(l);
        }
        issue.labels = labels;
      }
      issue.version += 1;
      return sendJson(ctx, 200, issueJson(repo, issue));
    }
    return sendErr(ctx, 404, 'Not Found');
  }

  // /issues/{n}/comments
  if (rest.length === 2 && rest[1] === 'comments') {
    if (method === 'GET') {
      return sendJson(ctx, 200, issue.comments.map((c) => commentJson(repo, issue, c)));
    }
    if (method === 'POST') {
      let input: Record<string, unknown>;
      try {
        input = parseJsonBody(body) as Record<string, unknown>;
      } catch {
        return sendErr(ctx, 400, 'Problems parsing JSON');
      }
      const text = typeof input.body === 'string' ? input.body : '';
      const comment = { id: nextCommentId, body: text };
      nextCommentId += 1;
      issue.comments.push(comment);
      issue.version += 1;
      return sendJson(ctx, 201, commentJson(repo, issue, comment));
    }
    return sendErr(ctx, 404, 'Not Found');
  }

  return sendErr(ctx, 404, 'Not Found');
}

// ---------------------------------------------------------------- pulls

async function handlePulls(ctx: Ctx, repo: Repo, rest: string[], body: Buffer): Promise<void> {
  const method = ctx.method;

  // /pulls — list or create.
  if (rest.length === 0) {
    if (method === 'GET') {
      const q = queryOf(ctx);
      const state = q.get('state') ?? 'open';
      let list = [...repo.pulls.values()];
      if (state === 'open') list = list.filter((p) => p.state === 'open');
      else if (state === 'closed') list = list.filter((p) => p.state === 'closed');
      list.sort((a, b) => b.seq - a.seq);
      const { page, link } = paginate(list.map((p) => pullJson(repo, p)), ctx);
      return sendJson(ctx, 200, page, link ? { link } : undefined);
    }
    if (method === 'POST') {
      let input: Record<string, unknown>;
      try {
        input = parseJsonBody(body) as Record<string, unknown>;
      } catch {
        return sendErr(ctx, 400, 'Problems parsing JSON');
      }
      const title = typeof input.title === 'string' ? input.title : '';
      const head = typeof input.head === 'string' ? input.head : '';
      const base = typeof input.base === 'string' ? input.base : repo.defaultBranch;
      if (title === '' || head === '') return sendErr(ctx, 422, 'Validation Failed');
      const headTip = branchTip(repo, head);
      const baseTip = branchTip(repo, base);
      if (!headTip || !baseTip) return sendErr(ctx, 422, 'Validation Failed: head or base branch does not exist');
      const dup = [...repo.pulls.values()].find((p) => p.state === 'open' && p.headRef === head && p.baseRef === base);
      if (dup) return sendErr(ctx, 422, 'Validation Failed: a pull request already exists for this head and base');
      const baseTree = treeAtRef(repo, base);
      const headTree = treeAtRef(repo, head);
      const seq = nextSeq();
      const pull: Pull = {
        id: nextPullId,
        number: repo.nextPull,
        title,
        body: typeof input.body === 'string' ? input.body : '',
        state: 'open',
        headRef: head,
        baseRef: base,
        headSha: headTip,
        baseSha: baseTip,
        mergeBaseSha: baseTip,
        merged: false,
        mergedAt: null,
        mergeCommitSha: null,
        files: diffTrees(repo, baseTree, headTree),
        seq,
      };
      nextPullId += 1;
      repo.nextPull += 1;
      repo.pulls.set(pull.number, pull);
      return sendJson(ctx, 201, pullJson(repo, pull));
    }
    return sendErr(ctx, 404, 'Not Found');
  }

  const num = Number(rest[0]);
  if (!Number.isInteger(num) || num <= 0) return sendErr(ctx, 404, 'Not Found');
  const pull = repo.pulls.get(num);

  // /pulls/{n}/files
  if (rest.length === 2 && rest[1] === 'files') {
    if (!pull) return sendErr(ctx, 404, 'Not Found');
    if (method !== 'GET') return sendErr(ctx, 404, 'Not Found');
    return sendJson(ctx, 200, pull.files);
  }

  // /pulls/{n}/merge
  if (rest.length === 2 && rest[1] === 'merge') {
    if (!pull) return sendErr(ctx, 404, 'Not Found');
    if (method !== 'PUT') return sendErr(ctx, 404, 'Not Found');
    if (pull.state !== 'open') return sendErr(ctx, 405, 'Pull request is already closed');
    if (pullConflicts(repo, pull)) return sendErr(ctx, 405, 'Merge conflict: the pull request cannot be merged');
    const sha = mergePullRequest(repo, pull);
    if (sha === null) return sendErr(ctx, 405, 'Merge conflict: the pull request cannot be merged');
    return sendJson(ctx, 200, { sha, merged: true, message: 'Pull request successfully merged' });
  }

  // /pulls/{n}
  if (rest.length === 1) {
    if (!pull) return sendErr(ctx, 404, 'Not Found');
    if (method !== 'GET') return sendErr(ctx, 404, 'Not Found');
    return sendJson(ctx, 200, pullJson(repo, pull));
  }

  return sendErr(ctx, 404, 'Not Found');
}

// ---------------------------------------------------------------- git: advertisements

function sortedRefs(repo: Repo): Array<{ name: string; oid: string }> {
  return [...repo.refs.entries()]
    .map(([name, oid]) => ({ name, oid }))
    .sort((a, b) => (a.name < b.name ? -1 : 1));
}

function v2UploadAdv(): Buffer {
  const key = 'v2-upload';
  const cached = advCache.get(key);
  if (cached) return cached;
  const buf = pktLines([
    '# service=git-upload-pack\n',
    'version 2\n',
    `agent=${AGENT}\n`,
    'ls-refs=unborn\n',
    'fetch=shallow wait-for-done\n',
    'server-option\n',
    'object-format=sha1\n',
    'flush',
  ]);
  advCache.set(key, buf);
  return buf;
}

function v0Adv(repo: Repo, service: 'git-upload-pack' | 'git-receive-pack'): Buffer {
  const key = `${service}:${repo.id}:${repo.refsVersion}`;
  const cached = advCache.get(key);
  if (cached) return cached;
  const caps =
    service === 'git-upload-pack'
      ? `symref=HEAD:refs/heads/${DEFAULT_BRANCH} agent=${AGENT} multi_ack thin-pack side-band side-band-64k ofs-delta shallow no-progress include-tag multi_ack_detailed object-format=sha1`
      : `symref=HEAD:refs/heads/${DEFAULT_BRANCH} agent=${AGENT} report-status side-band-64k delete-refs ofs-delta object-format=sha1`;
  const lines: Array<string | 'flush'> = [`# service=${service}\n`];
  const refs = sortedRefs(repo);
  const mainTip = repo.refs.get(`refs/heads/${DEFAULT_BRANCH}`);
  if (refs.length === 0) {
    lines.push(`${ZERO_OID} capabilities^{}\u0000${caps}\n`);
  } else {
    lines.push(`${mainTip ?? ZERO_OID} HEAD\u0000${caps}\n`);
    for (const r of refs) {
      if (r.name === 'HEAD') continue;
      lines.push(`${r.oid} ${r.name}\n`);
      if (r.name.startsWith('refs/tags/')) {
        const peeled = peelToCommit(repo, r.oid);
        if (peeled && peeled !== r.oid) lines.push(`${peeled} ${r.name}^{}\n`);
      }
    }
  }
  lines.push('flush');
  const buf = pktLines(lines);
  advCache.set(key, buf);
  return buf;
}

// ---------------------------------------------------------------- git: fetch planning

interface FetchPlan {
  objects: Map<string, GitObj>;
  shallow: string[];
  unshallow: string[];
}

// Objects to send for wants/haves/depth, plus shallow-info lines.
function planFetch(repo: Repo, wants: string[], haves: string[], depth: number | null, clientShallow: string[]): FetchPlan {
  // Commit levels from the wants (want = level 1).
  const levels = new Map<string, number>();
  const queue: Array<{ oid: string; level: number }> = [];
  for (const w of wants) {
    const obj = repo.objects.get(w);
    if (!obj) continue;
    if (obj.type === 'tag') {
      const peeled = peelToCommit(repo, w);
      if (peeled) queue.push({ oid: peeled, level: 1 });
    } else if (obj.type === 'commit') {
      queue.push({ oid: w, level: 1 });
    }
  }
  const includedCommits = new Set<string>();
  while (queue.length) {
    const { oid, level } = queue.shift() as { oid: string; level: number };
    if (levels.has(oid)) continue;
    if (depth !== null && level > depth) continue;
    levels.set(oid, level);
    includedCommits.add(oid);
    const obj = repo.objects.get(oid);
    if (!obj || obj.type !== 'commit') continue;
    for (const p of parseCommit(obj.data).parents) queue.push({ oid: p, level: level + 1 });
  }
  const included = new Set<string>();
  for (const w of wants) {
    if (repo.objects.has(w)) included.add(w);
  }
  // Depth-limited collection: for each included commit, add the commit, its
  // root tree and everything under that tree — but never its parents. Using
  // the full reachable closure here would leak history past the depth limit.
  for (const c of includedCommits) {
    included.add(c);
    const commitObj = repo.objects.get(c);
    if (!commitObj || commitObj.type !== 'commit') continue;
    const stack = [parseCommit(commitObj.data).tree];
    while (stack.length > 0) {
      const treeOid = stack.pop() as string;
      if (included.has(treeOid)) continue;
      included.add(treeOid);
      const treeObj = repo.objects.get(treeOid);
      if (!treeObj || treeObj.type !== 'tree') continue;
      for (const e of parseTree(treeObj.data)) {
        if (e.mode === '40000') stack.push(e.oid);
        else included.add(e.oid);
      }
    }
  }
  // Depth limit: commits at exactly the limit are shallow boundaries; their
  // trees/blobs are still included (they are in `included` above), but their
  // parents are not (the BFS stopped there).
  const shallow: string[] = [];
  if (depth !== null) {
    for (const [oid, level] of levels) if (level === depth) shallow.push(oid);
  }
  const unshallow: string[] = [];
  if (depth !== null) {
    for (const s of clientShallow) {
      if (levels.has(s) && (levels.get(s) as number) < depth) unshallow.push(s);
    }
  }
  // Objects the client already holds. A have that is also a shallow boundary
  // means the client holds that commit and its tree only — none of its
  // ancestors — so deepening must still deliver the parents. A plain have
  // means the full history below it is already held.
  const haveSet = new Set<string>();
  const shallowSet = new Set(clientShallow);
  for (const h of haves) {
    if (shallowSet.has(h)) {
      const obj = repo.objects.get(h);
      if (!obj) continue;
      haveSet.add(h);
      if (obj.type === 'commit') {
        const stack = [parseCommit(obj.data).tree];
        while (stack.length > 0) {
          const treeOid = stack.pop() as string;
          if (haveSet.has(treeOid)) continue;
          haveSet.add(treeOid);
          const treeObj = repo.objects.get(treeOid);
          if (!treeObj || treeObj.type !== 'tree') continue;
          for (const e of parseTree(treeObj.data)) {
            if (e.mode === '40000') stack.push(e.oid);
            else haveSet.add(e.oid);
          }
        }
      } else if (obj.type === 'tag') {
        const t = parseTagTarget(obj.data);
        if (t) haveSet.add(t.object);
      }
      continue;
    }
    for (const oid of collectReachable(repo, [h], true)) haveSet.add(oid);
  }
  const objects = new Map<string, GitObj>();
  for (const oid of included) {
    if (haveSet.has(oid)) continue;
    const obj = repo.objects.get(oid);
    if (obj) objects.set(oid, obj);
  }
  return { objects, shallow, unshallow };
}

function packKey(repo: Repo, wants: string[], haves: string[], depth: number | null, clientShallow: string[]): string {
  return `${repo.id}|${[...wants].sort().join(',')}|${[...haves].sort().join(',')}|${depth ?? ''}|${[...clientShallow].sort().join(',')}`;
}

function sidebandPack(pack: Buffer): Buffer {
  const parts: Buffer[] = [];
  const CHUNK = 65000;
  for (let off = 0; off < pack.length; off += CHUNK) {
    const slice = pack.subarray(off, Math.min(pack.length, off + CHUNK));
    const payload = Buffer.concat([Buffer.from([1]), slice]);
    parts.push(pktLine(payload));
  }
  if (pack.length === 0) parts.push(pktLine(Buffer.from([1])));
  return Buffer.concat(parts);
}

// ---------------------------------------------------------------- git: handlers

async function handleGit(ctx: Ctx, body: Buffer): Promise<void> {
  const m = /^\/([^/]+)\/([^/]+)\.git(\/.*)?$/.exec(ctx.path);
  if (!m) return sendErr(ctx, 404, 'Not Found');
  const owner = decodeSeg(m[1] as string);
  const name = decodeSeg(m[2] as string);
  const tail = m[3] ?? '';
  const repo = getRepo(owner, name);
  if (!repo) return sendErr(ctx, 404, 'Not Found');

  if (ctx.method === 'GET' && tail.startsWith('/info/refs')) {
    const service = queryOf(ctx).get('service');
    if (service !== 'git-upload-pack' && service !== 'git-receive-pack') {
      return sendErr(ctx, 400, 'Missing service');
    }
    const isV2 = ctx.req.headers['git-protocol'] === 'version=2' && service === 'git-upload-pack';
    const buf = isV2 ? v2UploadAdv() : v0Adv(repo, service);
    return sendRaw(ctx, 200, buf, `application/x-${service}-advertisement`);
  }

  if (ctx.method === 'POST' && tail === '/git-upload-pack') {
    return handleUploadPack(ctx, repo, body);
  }
  if (ctx.method === 'POST' && tail === '/git-receive-pack') {
    return handleReceivePack(ctx, repo, body);
  }
  return sendErr(ctx, 404, 'Not Found');
}

async function handleUploadPack(ctx: Ctx, repo: Repo, body: Buffer): Promise<void> {
  const isV2 = ctx.req.headers['git-protocol'] === 'version=2';
  const packets = decodePktLines(body);
  const lines: string[] = [];
  for (const p of packets) {
    if (p.kind === 'data') lines.push(p.payload.toString('utf8'));
  }
  if (lines.length === 0) return sendErr(ctx, 400, 'Empty request');

  if (isV2) {
    const command = (lines[0] ?? '').trim();
    if (command === 'command=ls-refs') return handleLsRefs(ctx, repo, lines.slice(1));
    if (command === 'command=fetch') return handleFetchV2(ctx, repo, lines.slice(1));
    return sendErr(ctx, 400, 'Unknown v2 command');
  }

  // v0: wants section, flush, haves/done section, flush.
  const wants: string[] = [];
  const haves: string[] = [];
  const shallow: string[] = [];
  let depth: number | null = null;
  let section = 0;
  for (const p of packets) {
    if (p.kind === 'flush') {
      section += 1;
      continue;
    }
    if (p.kind !== 'data') continue;
    const line = p.payload.toString('utf8').replace(/\n$/, '');
    if (line.startsWith('want ')) {
      const oid = line.slice(5, 45);
      if (isOid(oid)) wants.push(oid);
    } else if (line.startsWith('shallow ')) {
      shallow.push(line.slice(8).trim());
    } else if (line.startsWith('deepen ')) {
      const n = Number(line.slice(7).trim());
      if (Number.isFinite(n) && n > 0) depth = n;
    } else if (line.startsWith('have ')) {
      haves.push(line.slice(5, 45));
    }
  }
  if (wants.length === 0) return sendErr(ctx, 400, 'No wants');
  const key = `${packKey(repo, wants, haves, depth, shallow)}|v0`;
  const cached = fetchCache.get(key);
  if (cached) return sendRaw(ctx, 200, cached, 'application/x-git-upload-pack-result');
  const plan = planFetch(repo, wants, haves, depth, shallow);
  const parts: Buffer[] = [pktLine('NAK\n')];
  for (const s of plan.shallow) parts.push(pktLine(`shallow ${s}\n`));
  for (const s of plan.unshallow) parts.push(pktLine(`unshallow ${s}\n`));
  let pack = Buffer.alloc(0);
  if (plan.objects.size > 0) {
    const pkey = packKey(repo, wants, haves, depth, shallow);
    const cachedPack = packCache.get(pkey);
    if (cachedPack) {
      pack = cachedPack;
    } else {
      const ordered = [...plan.objects.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1));
      pack = writePack(ordered.map(([, o]) => o));
      packCache.set(pkey, pack);
    }
    parts.push(sidebandPack(pack));
  }
  parts.push(PKT_FLUSH);
  const out = Buffer.concat(parts);
  fetchCache.set(key, out);
  return sendRaw(ctx, 200, out, 'application/x-git-upload-pack-result');
}

async function handleLsRefs(ctx: Ctx, repo: Repo, args: string[]): Promise<void> {
  let peel = false;
  let symrefs = false;
  let unborn = false;
  const prefixes: string[] = [];
  let seenDelim = false;
  for (const raw of args) {
    const line = raw.replace(/\n$/, '');
    if (line === '') continue;
    if (line === 'peel') peel = true;
    else if (line === 'symrefs') symrefs = true;
    else if (line === 'unborn') unborn = true;
    else if (line.startsWith('ref-prefix ')) prefixes.push(line.slice('ref-prefix '.length));
    void seenDelim;
  }
  const keep = (name: string): boolean => prefixes.length === 0 || prefixes.some((p) => name.startsWith(p));
  const lines: Array<string | 'flush'> = [];
  const mainTip = repo.refs.get(`refs/heads/${DEFAULT_BRANCH}`);
  if (mainTip) {
    if (keep('HEAD')) {
      lines.push(`${mainTip} HEAD${symrefs ? ` symref-target:refs/heads/${DEFAULT_BRANCH}` : ''}\n`);
    }
  } else if (unborn) {
    if (keep('HEAD')) {
      lines.push(`unborn HEAD${symrefs ? ` symref-target:refs/heads/${DEFAULT_BRANCH}` : ''}\n`);
    }
  }
  for (const r of sortedRefs(repo)) {
    if (!keep(r.name)) continue;
    let line = `${r.oid} ${r.name}`;
    if (symrefs && r.name === `refs/heads/${DEFAULT_BRANCH}`) line += '';
    if (peel && r.name.startsWith('refs/tags/')) {
      const peeled = peelToCommit(repo, r.oid);
      if (peeled && peeled !== r.oid) line += ` peeled:${peeled}`;
    }
    lines.push(`${line}\n`);
  }
  lines.push('flush');
  return sendRaw(ctx, 200, pktLines(lines), 'application/x-git-upload-pack-result');
}

async function handleFetchV2(ctx: Ctx, repo: Repo, args: string[]): Promise<void> {
  const wants: string[] = [];
  const haves: string[] = [];
  const shallow: string[] = [];
  let depth: number | null = null;
  let inArgs = false;
  for (const raw of args) {
    const line = raw.replace(/\n$/, '');
    if (line === '') continue;
    if (!inArgs) {
      // command line already consumed; first non-command lines are agent etc.
      if (line.startsWith('command=')) continue;
      inArgs = true;
    }
    if (line.startsWith('want ')) wants.push(line.slice(5).trim());
    else if (line.startsWith('have ')) haves.push(line.slice(5).trim());
    else if (line.startsWith('shallow ')) shallow.push(line.slice(8).trim());
    else if (line.startsWith('deepen ')) {
      const n = Number(line.slice(7).trim());
      if (Number.isFinite(n) && n > 0) depth = n;
    }
  }
  if (wants.length === 0) {
    const out = pktLines(['acknowledgments\n', 'NAK\n', 'delim', 'flush']);
    return sendRaw(ctx, 200, out, 'application/x-git-upload-pack-result');
  }
  const key = `${packKey(repo, wants, haves, depth, shallow)}|v2`;
  const cached = fetchCache.get(key);
  if (cached) return sendRaw(ctx, 200, cached, 'application/x-git-upload-pack-result');
  const plan = planFetch(repo, wants, haves, depth, shallow);
  const parts: Buffer[] = [];
  parts.push(pktLine('acknowledgments\n'));
  parts.push(pktLine('NAK\n'));
  parts.push(PKT_DELIM);
  if (plan.shallow.length > 0 || plan.unshallow.length > 0) {
    parts.push(pktLine('shallow-info\n'));
    for (const s of plan.shallow) parts.push(pktLine(`shallow ${s}\n`));
    for (const s of plan.unshallow) parts.push(pktLine(`unshallow ${s}\n`));
    parts.push(PKT_DELIM);
  }
  if (plan.objects.size > 0) {
    const pkey = packKey(repo, wants, haves, depth, shallow);
    let pack = packCache.get(pkey);
    if (!pack) {
      const ordered = [...plan.objects.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1));
      pack = writePack(ordered.map(([, o]) => o));
      packCache.set(pkey, pack);
    }
    parts.push(pktLine('packfile\n'));
    parts.push(sidebandPack(pack));
  }
  parts.push(PKT_FLUSH);
  const out = Buffer.concat(parts);
  fetchCache.set(key, out);
  return sendRaw(ctx, 200, out, 'application/x-git-upload-pack-result');
}

interface PushCmd {
  oldOid: string;
  newOid: string;
  ref: string;
}

async function handleReceivePack(ctx: Ctx, repo: Repo, body: Buffer): Promise<void> {
  const { packets, rawAt } = splitPktAndRaw(body);
  const commands: PushCmd[] = [];
  let malformed = false;
  for (const p of packets) {
    if (p.kind !== 'data') continue;
    const text = p.payload.toString('utf8').replace(/\n$/, '');
    const nul = text.indexOf('\u0000');
    const main = nul >= 0 ? text.slice(0, nul) : text;
    const parts = main.split(' ');
    if (parts.length < 3 || !isOid(parts[0] as string) || !isOid(parts[1] as string)) {
      malformed = true;
      continue;
    }
    commands.push({ oldOid: parts[0] as string, newOid: parts[1] as string, ref: parts.slice(2).join(' ') });
  }
  const packBytes = body.subarray(rawAt);
  const reportLines: string[] = [];
  let unpackOk = true;
  let unpackDetail = 'ok';
  if (malformed || commands.length === 0) {
    unpackOk = false;
    unpackDetail = 'unpacker error';
  } else if (packBytes.length > 0) {
    try {
      const objects = readPack(packBytes, (oid) => repo.objects.get(oid));
      for (const [oid, obj] of objects) {
        if (!repo.objects.has(oid)) repo.objects.set(oid, obj);
      }
    } catch {
      unpackOk = false;
      unpackDetail = 'unpacker error';
    }
  }
  const results: Array<{ ref: string; ok: boolean; reason: string }> = [];
  if (unpackOk) {
    for (const cmd of commands) {
      const current = repo.refs.get(cmd.ref);
      if (cmd.newOid === ZERO_OID) {
        // Delete.
        if (!current) {
          results.push({ ref: cmd.ref, ok: false, reason: 'remote ref does not exist' });
        } else if (current !== cmd.oldOid) {
          results.push({ ref: cmd.ref, ok: false, reason: 'non-fast-forward' });
        } else {
          repo.refs.delete(cmd.ref);
          results.push({ ref: cmd.ref, ok: true, reason: '' });
        }
        continue;
      }
      const target = repo.objects.get(cmd.newOid);
      if (!target || (target.type !== 'commit' && target.type !== 'tag')) {
        results.push({ ref: cmd.ref, ok: false, reason: 'object not found' });
        continue;
      }
      if (cmd.oldOid === ZERO_OID) {
        // Create.
        if (current) {
          results.push({ ref: cmd.ref, ok: false, reason: 'already exists' });
        } else {
          repo.refs.set(cmd.ref, cmd.newOid);
          results.push({ ref: cmd.ref, ok: true, reason: '' });
        }
        continue;
      }
      // Update: must match current and fast-forward.
      if (current !== cmd.oldOid) {
        results.push({ ref: cmd.ref, ok: false, reason: 'non-fast-forward' });
        continue;
      }
      const newCommit = target.type === 'tag' ? peelToCommit(repo, cmd.newOid) : cmd.newOid;
      if (newCommit === null || !isAncestor(repo, current, newCommit)) {
        results.push({ ref: cmd.ref, ok: false, reason: 'non-fast-forward' });
        continue;
      }
      repo.refs.set(cmd.ref, cmd.newOid);
      results.push({ ref: cmd.ref, ok: true, reason: '' });
    }
    if (results.some((r) => r.ok)) bumpRefs(repo);
  } else {
    for (const cmd of commands) results.push({ ref: cmd.ref, ok: false, reason: unpackDetail });
  }
  reportLines.push(`unpack ${unpackOk ? 'ok' : unpackDetail}\n`);
  for (const r of results) {
    reportLines.push(r.ok ? `ok ${r.ref}\n` : `ng ${r.ref} ${r.reason}\n`);
  }
  const reportStream = pktLines([...reportLines, 'flush']);
  const parts: Buffer[] = [];
  const CHUNK = 65000;
  for (let off = 0; off < reportStream.length; off += CHUNK) {
    const slice = reportStream.subarray(off, Math.min(reportStream.length, off + CHUNK));
    parts.push(pktLine(Buffer.concat([Buffer.from([1]), slice])));
  }
  parts.push(PKT_FLUSH);
  return sendRaw(ctx, 200, Buffer.concat(parts), 'application/x-git-receive-pack-result');
}

// ---------------------------------------------------------------- graphql parser

interface GqlField {
  kind: 'field';
  alias?: string;
  name: string;
  args: Record<string, unknown>;
  selections?: GqlSel[];
}
interface GqlSpread {
  kind: 'spread';
  name: string;
}
interface GqlInline {
  kind: 'inline';
  typeCond?: string;
  selections: GqlSel[];
}
type GqlSel = GqlField | GqlSpread | GqlInline;
interface GqlOp {
  kind: 'query' | 'mutation' | 'subscription';
  name?: string;
  varDefs: Record<string, unknown>;
  selections: GqlSel[];
}
interface GqlFrag {
  name: string;
  typeCond: string;
  selections: GqlSel[];
}

type Tok =
  | { t: 'punct'; v: string }
  | { t: 'name'; v: string }
  | { t: 'int'; v: number }
  | { t: 'float'; v: number }
  | { t: 'string'; v: string };

function gqlLex(src: string): Tok[] {
  const toks: Tok[] = [];
  let i = 0;
  while (i < src.length) {
    const c = src[i] as string;
    if (c === ' ' || c === '\t' || c === '\n' || c === '\r' || c === ',') {
      i += 1;
      continue;
    }
    if (c === '#') {
      while (i < src.length && src[i] !== '\n') i += 1;
      continue;
    }
    if (c === '.' && src.slice(i, i + 3) === '...') {
      toks.push({ t: 'punct', v: '...' });
      i += 3;
      continue;
    }
    if ('{}()[]:!=$@|&'.includes(c)) {
      toks.push({ t: 'punct', v: c });
      i += 1;
      continue;
    }
    if (c === '"') {
      let j = i + 1;
      let out = '';
      while (j < src.length && src[j] !== '"') {
        if (src[j] === '\\' && j + 1 < src.length) {
          const e = src[j + 1] as string;
          out += e === 'n' ? '\n' : e === 't' ? '\t' : e === 'r' ? '\r' : e;
          j += 2;
        } else {
          out += src[j] as string;
          j += 1;
        }
      }
      toks.push({ t: 'string', v: out });
      i = j + 1;
      continue;
    }
    if (/[0-9-]/.test(c)) {
      let j = i;
      while (j < src.length && /[0-9.eE+-]/.test(src[j] as string)) j += 1;
      const raw = src.slice(i, j);
      if (raw.includes('.') || raw.includes('e') || raw.includes('E')) toks.push({ t: 'float', v: Number(raw) });
      else toks.push({ t: 'int', v: Number(raw) });
      i = j;
      continue;
    }
    if (/[A-Za-z_]/.test(c)) {
      let j = i;
      while (j < src.length && /[A-Za-z0-9_]/.test(src[j] as string)) j += 1;
      toks.push({ t: 'name', v: src.slice(i, j) });
      i = j;
      continue;
    }
    i += 1;
  }
  return toks;
}

class GqlParser {
  private pos = 0;
  private toks: Tok[];
  constructor(toks: Tok[]) {
    this.toks = toks;
  }

  private peek(): Tok | null {
    return this.toks[this.pos] ?? null;
  }
  private next(): Tok {
    const t = this.toks[this.pos];
    this.pos += 1;
    if (!t) throw new Error('unexpected end of query');
    return t;
  }
  private expectPunct(v: string): void {
    const t = this.next();
    if (t.t !== 'punct' || t.v !== v) throw new Error(`expected ${v}`);
  }
  private isPunct(v: string): boolean {
    const t = this.peek();
    return t !== null && t.t === 'punct' && t.v === v;
  }
  private expectName(): string {
    const t = this.next();
    if (t.t !== 'name') throw new Error('expected name');
    return t.v;
  }

  parseDocument(): { ops: GqlOp[]; frags: Map<string, GqlFrag> } {
    const ops: GqlOp[] = [];
    const frags = new Map<string, GqlFrag>();
    while (this.pos < this.toks.length) {
      const t = this.peek();
      if (!t) break;
      if (t.t === 'punct' && t.v === '{') {
        ops.push({ kind: 'query', varDefs: {}, selections: this.parseSelections() });
        continue;
      }
      if (t.t === 'name' && (t.v === 'query' || t.v === 'mutation' || t.v === 'subscription')) {
        const kind = t.v as 'query' | 'mutation' | 'subscription';
        this.next();
        let name: string | undefined;
        const nt = this.peek();
        if (nt && nt.t === 'name') {
          name = this.next().v as string;
        }
        const varDefs = this.parseVarDefs();
        ops.push({ kind, name, varDefs, selections: this.parseSelections() });
        continue;
      }
      if (t.t === 'name' && t.v === 'fragment') {
        this.next();
        const name = this.expectName();
        this.expectName(); // 'on'
        const typeCond = this.expectName();
        frags.set(name, { name, typeCond, selections: this.parseSelections() });
        continue;
      }
      this.next();
    }
    return { ops, frags };
  }

  private parseVarDefs(): Record<string, unknown> {
    const defs: Record<string, unknown> = {};
    if (!this.isPunct('(')) return defs;
    this.next();
    while (!this.isPunct(')')) {
      if (this.pos >= this.toks.length) break;
      this.expectPunct('$');
      const name = this.expectName();
      this.expectPunct(':');
      // Skip the type (name, possibly [..] / !).
      let depth = 0;
      while (this.pos < this.toks.length) {
        const t = this.peek() as Tok;
        if (t.t === 'punct' && (t.v === '[' || t.v === '(')) depth += 1;
        else if (t.t === 'punct' && (t.v === ']' || t.v === ')')) {
          if (depth === 0) break;
          depth -= 1;
        } else if (depth === 0 && t.t === 'punct' && (t.v === '=' || t.v === ',')) break;
        else if (depth === 0 && t.t === 'name' && (t.v === 'query' || t.v === 'mutation')) break;
        this.next();
      }
      if (this.isPunct('=')) {
        this.next();
        defs[name] = this.parseValue();
      } else {
        defs[name] = null;
      }
      if (this.isPunct(',')) this.next();
    }
    this.expectPunct(')');
    return defs;
  }

  private parseSelections(): GqlSel[] {
    this.expectPunct('{');
    const sels: GqlSel[] = [];
    while (!this.isPunct('}')) {
      if (this.pos >= this.toks.length) break;
      sels.push(this.parseSelection());
    }
    this.expectPunct('}');
    return sels;
  }

  private parseSelection(): GqlSel {
    if (this.isPunct('...')) {
      this.next();
      const t = this.peek();
      if (t && t.t === 'name' && t.v === 'on') {
        this.next();
        const typeCond = this.expectName();
        return { kind: 'inline', typeCond, selections: this.parseSelections() };
      }
      if (t && t.t === 'name') {
        return { kind: 'spread', name: this.next().v as string };
      }
      return { kind: 'inline', selections: this.parseSelections() };
    }
    let alias: string | undefined;
    let name = this.expectName();
    if (this.isPunct(':')) {
      this.next();
      alias = name;
      name = this.expectName();
    }
    const args = this.parseArgs();
    let selections: GqlSel[] | undefined;
    if (this.isPunct('{')) selections = this.parseSelections();
    return { kind: 'field', alias, name, args, selections };
  }

  private parseArgs(): Record<string, unknown> {
    const args: Record<string, unknown> = {};
    if (!this.isPunct('(')) return args;
    this.next();
    while (!this.isPunct(')')) {
      if (this.pos >= this.toks.length) break;
      const name = this.expectName();
      this.expectPunct(':');
      args[name] = this.parseValue();
      if (this.isPunct(',')) this.next();
    }
    this.expectPunct(')');
    return args;
  }

  private parseValue(): unknown {
    const t = this.next();
    if (t.t === 'punct' && t.v === '$') return { __var: this.expectName() };
    if (t.t === 'punct' && t.v === '[') {
      const list: unknown[] = [];
      while (!this.isPunct(']')) {
        if (this.pos >= this.toks.length) break;
        list.push(this.parseValue());
        if (this.isPunct(',')) this.next();
      }
      this.expectPunct(']');
      return list;
    }
    if (t.t === 'punct' && t.v === '{') {
      const obj: Record<string, unknown> = {};
      while (!this.isPunct('}')) {
        if (this.pos >= this.toks.length) break;
        const k = this.expectName();
        this.expectPunct(':');
        obj[k] = this.parseValue();
        if (this.isPunct(',')) this.next();
      }
      this.expectPunct('}');
      return obj;
    }
    if (t.t === 'string') return t.v;
    if (t.t === 'int' || t.t === 'float') return t.v;
    if (t.t === 'name') {
      if (t.v === 'true') return true;
      if (t.v === 'false') return false;
      if (t.v === 'null') return null;
      return t.v; // enum value
    }
    throw new Error('unexpected value token');
  }
}

// ---------------------------------------------------------------- graphql executor

const GQL_FIELDS: Record<string, Set<string>> = {
  Query: new Set(['viewer', 'repository', 'node', '__type', '__schema', '__typename']),
  Mutation: new Set(['createIssue', 'closeIssue', 'createPullRequest', 'mergePullRequest', 'addComment', '__typename']),
  User: new Set(['id', 'login', 'name', 'email', 'databaseId', 'url', 'avatarUrl', '__typename']),
  Repository: new Set(['id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef', 'viewerPermission', 'hasIssuesEnabled', 'issue', 'issues', 'pullRequest', 'pullRequests', 'description', 'createdAt', 'updatedAt', 'url', '__typename']),
  Issue: new Set(['id', 'databaseId', 'number', 'title', 'body', 'state', 'createdAt', 'updatedAt', 'closedAt', 'author', 'labels', 'comments', 'url', '__typename']),
  PullRequest: new Set(['id', 'databaseId', 'number', 'title', 'body', 'state', 'merged', 'mergeable', 'headRefName', 'baseRefName', 'headRef', 'baseRef', 'files', 'mergedAt', 'createdAt', 'updatedAt', 'author', '__typename']),
  Ref: new Set(['name', 'target', '__typename']),
  IssueConnection: new Set(['nodes', 'edges', 'totalCount', 'pageInfo', '__typename']),
  PullRequestConnection: new Set(['nodes', 'edges', 'totalCount', 'pageInfo', '__typename']),
  ChangedFileConnection: new Set(['nodes', 'edges', 'totalCount', 'pageInfo', '__typename']),
  LabelConnection: new Set(['nodes', 'edges', 'totalCount', 'pageInfo', '__typename']),
  CommentConnection: new Set(['nodes', 'edges', 'totalCount', 'pageInfo', '__typename']),
  IssueEdge: new Set(['node', 'cursor', '__typename']),
  PullRequestEdge: new Set(['node', 'cursor', '__typename']),
  ChangedFileEdge: new Set(['node', 'cursor', '__typename']),
  LabelEdge: new Set(['node', 'cursor', '__typename']),
  CommentEdge: new Set(['node', 'cursor', '__typename']),
  Label: new Set(['id', 'name', 'color', 'description', '__typename']),
  ChangedFile: new Set(['path', 'filename', 'additions', 'deletions', 'changes', 'status', '__typename']),
  PageInfo: new Set(['hasNextPage', 'hasPreviousPage', 'startCursor', 'endCursor', '__typename']),
  Comment: new Set(['id', 'body', 'createdAt', 'author', 'url', 'databaseId', '__typename']),
  CreateIssuePayload: new Set(['issue', 'clientMutationId', '__typename']),
  CloseIssuePayload: new Set(['issue', 'clientMutationId', '__typename']),
  CreatePullRequestPayload: new Set(['pullRequest', 'clientMutationId', '__typename']),
  MergePullRequestPayload: new Set(['pullRequest', 'clientMutationId', '__typename']),
  AddCommentPayload: new Set(['commentEdge', 'comment', 'clientMutationId', '__typename']),
  __Type: new Set(['name', 'kind', 'description', 'fields', 'enumValues', 'possibleTypes', 'inputFields', '__typename']),
  __Field: new Set(['name', 'description', 'args', 'type', '__typename']),
  __EnumValue: new Set(['name', 'description', '__typename']),
  __InputValue: new Set(['name', 'description', 'type', 'defaultValue', '__typename']),
  __Schema: new Set(['queryType', 'mutationType', 'types', 'directives', '__typename']),
};

const TYPE_INFO: Record<string, { kind: string; fields?: string[]; enumValues?: string[] }> = {
  Issue: { kind: 'OBJECT', fields: ['id', 'databaseId', 'number', 'title', 'body', 'state', 'createdAt', 'updatedAt', 'closedAt', 'author', 'labels', 'comments', 'url'] },
  PullRequest: { kind: 'OBJECT', fields: ['id', 'databaseId', 'number', 'title', 'body', 'state', 'merged', 'mergeable', 'headRefName', 'baseRefName', 'headRef', 'baseRef', 'files', 'mergedAt', 'createdAt', 'updatedAt', 'author'] },
  Repository: { kind: 'OBJECT', fields: ['id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef', 'viewerPermission', 'hasIssuesEnabled', 'issue', 'issues', 'pullRequest', 'pullRequests', 'description', 'createdAt', 'updatedAt', 'url'] },
  User: { kind: 'OBJECT', fields: ['id', 'login', 'name', 'email', 'databaseId', 'url', 'avatarUrl'] },
  SearchType: { kind: 'ENUM', enumValues: ['ISSUE', 'USER', 'REPOSITORY', 'DISCUSSION', 'CODE'] },
  IssueState: { kind: 'ENUM', enumValues: ['OPEN', 'CLOSED'] },
  PullRequestState: { kind: 'ENUM', enumValues: ['OPEN', 'CLOSED', 'MERGED'] },
  MergeableState: { kind: 'ENUM', enumValues: ['CONFLICTING', 'MERGEABLE', 'UNKNOWN'] },
};

interface GqlExecCtx {
  errors: Array<Record<string, unknown>>;
  frags: Map<string, GqlFrag>;
  variables: Record<string, unknown>;
}

function resolveArg(v: unknown, variables: Record<string, unknown>): unknown {
  if (v !== null && typeof v === 'object') {
    if (Array.isArray(v)) return v.map((x) => resolveArg(x, variables));
    const rec = v as Record<string, unknown>;
    if (typeof rec.__var === 'string') {
      const name = rec.__var as string;
      return name in variables ? variables[name] : null;
    }
    const out: Record<string, unknown> = {};
    for (const [k, val] of Object.entries(rec)) out[k] = resolveArg(val, variables);
    return out;
  }
  return v;
}

function findRepoById(id: number): Repo | null {
  for (const r of repos.values()) if (r.id === id) return r;
  return null;
}
function findIssueById(id: number): { repo: Repo; issue: Issue } | null {
  for (const r of repos.values()) {
    for (const i of r.issues.values()) if (i.id === id) return { repo: r, issue: i };
  }
  return null;
}
function findPullById(id: number): { repo: Repo; pull: Pull } | null {
  for (const r of repos.values()) {
    for (const p of r.pulls.values()) if (p.id === id) return { repo: r, pull: p };
  }
  return null;
}

function viewerObj(): Record<string, unknown> {
  return { __type: 'User', login: VIEWER_LOGIN, id: VIEWER_ID, name: VIEWER_NAME, email: VIEWER_EMAIL };
}
function repoObj(repo: Repo): Record<string, unknown> {
  return { __type: 'Repository', repo };
}
function issueObj(repo: Repo, issue: Issue): Record<string, unknown> {
  return { __type: 'Issue', repo, issue };
}
function pullObj(repo: Repo, pull: Pull): Record<string, unknown> {
  return { __type: 'PullRequest', repo, pull };
}
function encodeCursor(n: number): string {
  return b64encode(Buffer.from(`issue:${n}`, 'utf8'));
}
function decodeCursor(c: string): number | null {
  try {
    const s = b64decode(c).toString('utf8');
    const m = /^issue:(\d+)$/.exec(s);
    return m ? Number(m[1]) : null;
  } catch {
    return null;
  }
}

function issuesConnection(repo: Repo, args: Record<string, unknown>): Record<string, unknown> {
  let list = [...repo.issues.values()];
  const states = args.states;
  if (Array.isArray(states) && states.length > 0) {
    const wanted = new Set(states.map((s) => String(s).toLowerCase()));
    list = list.filter((i) => wanted.has(i.state));
  }
  const orderBy = args.orderBy as Record<string, unknown> | undefined;
  const direction = orderBy && typeof orderBy.direction === 'string' ? orderBy.direction : 'DESC';
  list.sort((a, b) => (direction === 'ASC' ? a.seq - b.seq : b.seq - a.seq));
  const after = args.after;
  if (typeof after === 'string') {
    const n = decodeCursor(after);
    if (n !== null) {
      list = list.filter((i) => (direction === 'ASC' ? i.number > n : i.number < n));
    }
  }
  const first = typeof args.first === 'number' ? args.first : 30;
  const taken = list.slice(0, Math.max(0, first));
  const hasNext = list.length > taken.length;
  const endCursor = taken.length > 0 ? encodeCursor((taken[taken.length - 1] as Issue).number) : null;
  return {
    __type: 'IssueConnection',
    nodes: taken.map((i) => issueObj(repo, i)),
    edges: taken.map((i) => ({ __type: 'IssueEdge', node: issueObj(repo, i), cursor: encodeCursor(i.number) })),
    totalCount: repo.issues.size,
    pageInfo: { __type: 'PageInfo', hasNextPage: hasNext, hasPreviousPage: false, startCursor: taken.length > 0 ? encodeCursor((taken[0] as Issue).number) : null, endCursor },
  };
}

function pullsConnection(repo: Repo, args: Record<string, unknown>): Record<string, unknown> {
  let list = [...repo.pulls.values()].sort((a, b) => b.seq - a.seq);
  const states = args.states;
  if (Array.isArray(states) && states.length > 0) {
    const wanted = new Set(states.map((s) => String(s).toLowerCase()));
    list = list.filter((p) => wanted.has(p.state));
  }
  const after = args.after;
  if (typeof after === 'string') {
    const n = decodeCursor(after);
    if (n !== null) list = list.filter((p) => p.number < n);
  }
  const first = typeof args.first === 'number' ? args.first : 30;
  const taken = list.slice(0, Math.max(0, first));
  const hasNext = list.length > taken.length;
  const endCursor = taken.length > 0 ? encodeCursor((taken[taken.length - 1] as Pull).number) : null;
  return {
    __type: 'PullRequestConnection',
    nodes: taken.map((p) => pullObj(repo, p)),
    edges: taken.map((p) => ({ __type: 'PullRequestEdge', node: pullObj(repo, p), cursor: encodeCursor(p.number) })),
    totalCount: repo.pulls.size,
    pageInfo: { __type: 'PageInfo', hasNextPage: hasNext, hasPreviousPage: false, startCursor: taken.length > 0 ? encodeCursor((taken[0] as Pull).number) : null, endCursor },
  };
}

function filesConnection(repo: Repo, pull: Pull, args: Record<string, unknown>): Record<string, unknown> {
  const first = typeof args.first === 'number' ? args.first : 30;
  const taken = pull.files.slice(0, Math.max(0, first));
  const nodes = taken.map((f) => ({
    __type: 'ChangedFile',
    path: f.filename,
    filename: f.filename,
    additions: f.additions,
    deletions: f.deletions,
    changes: f.changes,
    status: f.status,
  }));
  return {
    __type: 'ChangedFileConnection',
    nodes,
    edges: nodes.map((n) => ({ __type: 'ChangedFileEdge', node: n, cursor: '' })),
    totalCount: pull.files.length,
    pageInfo: { __type: 'PageInfo', hasNextPage: pull.files.length > taken.length, hasPreviousPage: false, startCursor: null, endCursor: null },
  };
}

function createIssueGql(repo: Repo, title: string, body: string): Issue {
  const seq = nextSeq();
  const issue: Issue = {
    id: nextIssueId,
    number: repo.nextIssue,
    title,
    body,
    state: 'open',
    labels: [],
    comments: [],
    seq,
    version: 1,
  };
  nextIssueId += 1;
  repo.nextIssue += 1;
  repo.issues.set(issue.number, issue);
  return issue;
}

function createPullGql(repo: Repo, title: string, head: string, base: string): Pull | null {
  const headTip = branchTip(repo, head);
  const baseTip = branchTip(repo, base);
  if (!headTip || !baseTip) return null;
  const dup = [...repo.pulls.values()].find((p) => p.state === 'open' && p.headRef === head && p.baseRef === base);
  if (dup) return dup;
  const seq = nextSeq();
  const pull: Pull = {
    id: nextPullId,
    number: repo.nextPull,
    title,
    body: '',
    state: 'open',
    headRef: head,
    baseRef: base,
    headSha: headTip,
    baseSha: baseTip,
    mergeBaseSha: baseTip,
    merged: false,
    mergedAt: null,
    mergeCommitSha: null,
    files: diffTrees(repo, treeAtRef(repo, base), treeAtRef(repo, head)),
    seq,
  };
  nextPullId += 1;
  repo.nextPull += 1;
  repo.pulls.set(pull.number, pull);
  return pull;
}

function resolveField(typeName: string, obj: Record<string, unknown>, field: GqlField, ctx: GqlExecCtx): unknown {
  const args: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(field.args)) args[k] = resolveArg(v, ctx.variables);

  if (field.name === '__typename') return typeName;

  if (typeName === 'Query') {
    if (field.name === 'viewer') return viewerObj();
    if (field.name === 'repository') {
      const owner = args.owner as string | undefined;
      const name = args.name as string | undefined;
      if (typeof owner !== 'string' || typeof name !== 'string') return null;
      const repo = getRepo(owner, name);
      return repo ? repoObj(repo) : null;
    }
    if (field.name === 'node') {
      const id = args.id as string | undefined;
      if (typeof id !== 'string') return null;
      const parsed = parseGid(id);
      if (!parsed) return null;
      if (parsed.kind === 'Repository') {
        const repo = findRepoById(parsed.num);
        return repo ? repoObj(repo) : null;
      }
      if (parsed.kind === 'Issue') {
        const found = findIssueById(parsed.num);
        return found ? issueObj(found.repo, found.issue) : null;
      }
      if (parsed.kind === 'PullRequest') {
        const found = findPullById(parsed.num);
        return found ? pullObj(found.repo, found.pull) : null;
      }
      return null;
    }
    if (field.name === '__type') {
      const name = args.name as string | undefined;
      if (typeof name !== 'string') return null;
      const info = TYPE_INFO[name];
      if (!info) return null;
      return {
        __type: '__Type',
        name,
        kind: info.kind,
        description: null,
        fields: info.fields ? info.fields.map((f) => ({ __type: '__Field', name: f, description: null, args: [], type: { __type: '__Type', name: 'String', kind: 'SCALAR' } })) : null,
        enumValues: info.enumValues ? info.enumValues.map((e) => ({ __type: '__EnumValue', name: e, description: null })) : null,
        possibleTypes: null,
        inputFields: null,
      };
    }
    if (field.name === '__schema') {
      return {
        __type: '__Schema',
        queryType: { __type: '__Type', name: 'Query', kind: 'OBJECT' },
        mutationType: { __type: '__Type', name: 'Mutation', kind: 'OBJECT' },
        types: [],
        directives: [],
      };
    }
    return null;
  }

  if (typeName === 'Mutation') {
    const input = (args.input ?? {}) as Record<string, unknown>;
    if (field.name === 'createIssue') {
      const repoId = typeof input.repositoryId === 'string' ? parseGid(input.repositoryId) : null;
      const repo = repoId && repoId.kind === 'Repository' ? findRepoById(repoId.num) : null;
      if (!repo) return { __type: 'CreateIssuePayload', issue: null };
      const issue = createIssueGql(repo, typeof input.title === 'string' ? input.title : '', typeof input.body === 'string' ? input.body : '');
      return { __type: 'CreateIssuePayload', issue: issueObj(repo, issue) };
    }
    if (field.name === 'closeIssue') {
      const issueId = typeof input.issueId === 'string' ? parseGid(input.issueId) : null;
      const found = issueId && issueId.kind === 'Issue' ? findIssueById(issueId.num) : null;
      if (!found) return { __type: 'CloseIssuePayload', issue: null };
      found.issue.state = 'closed';
      found.issue.version += 1;
      return { __type: 'CloseIssuePayload', issue: issueObj(found.repo, found.issue) };
    }
    if (field.name === 'createPullRequest') {
      const repoId = typeof input.repositoryId === 'string' ? parseGid(input.repositoryId) : null;
      const repo = repoId && repoId.kind === 'Repository' ? findRepoById(repoId.num) : null;
      if (!repo) return { __type: 'CreatePullRequestPayload', pullRequest: null };
      const pull = createPullGql(
        repo,
        typeof input.title === 'string' ? input.title : '',
        typeof input.headRefName === 'string' ? input.headRefName : '',
        typeof input.baseRefName === 'string' ? input.baseRefName : repo.defaultBranch,
      );
      return { __type: 'CreatePullRequestPayload', pullRequest: pull ? pullObj(repo, pull) : null };
    }
    if (field.name === 'mergePullRequest') {
      const prId = typeof input.pullRequestId === 'string' ? parseGid(input.pullRequestId) : null;
      const found = prId && prId.kind === 'PullRequest' ? findPullById(prId.num) : null;
      if (!found) return { __type: 'MergePullRequestPayload', pullRequest: null };
      if (found.pull.state !== 'open' || pullConflicts(found.repo, found.pull)) {
        ctx.errors.push({ message: 'Merge conflict: the pull request cannot be merged' });
        return { __type: 'MergePullRequestPayload', pullRequest: pullObj(found.repo, found.pull) };
      }
      mergePullRequest(found.repo, found.pull);
      return { __type: 'MergePullRequestPayload', pullRequest: pullObj(found.repo, found.pull) };
    }
    if (field.name === 'addComment') {
      const subjectId = typeof input.subjectId === 'string' ? parseGid(input.subjectId) : null;
      const found = subjectId && subjectId.kind === 'Issue' ? findIssueById(subjectId.num) : null;
      if (!found) return { __type: 'AddCommentPayload', commentEdge: null, comment: null };
      const comment = { id: nextCommentId, body: typeof input.body === 'string' ? input.body : '' };
      nextCommentId += 1;
      found.issue.comments.push(comment);
      found.issue.version += 1;
      const node = { __type: 'Comment', id: comment.id, body: comment.body, repo: found.repo, issue: found.issue };
      return { __type: 'AddCommentPayload', commentEdge: { __type: 'CommentEdge', node, cursor: '' }, comment: node };
    }
    return null;
  }

  if (typeName === 'User') {
    if (field.name === 'id') return gid('User', Number(obj.id ?? 0));
    if (field.name === 'databaseId') return Number(obj.id ?? 0);
    if (field.name === 'login') return obj.login ?? null;
    if (field.name === 'name') return obj.name ?? obj.login ?? null;
    if (field.name === 'email') return obj.email ?? null;
    if (field.name === 'url') return `https://github.com/${obj.login ?? ''}`;
    if (field.name === 'avatarUrl') return null;
    return null;
  }

  if (typeName === 'Repository') {
    const repo = obj.repo as Repo;
    if (field.name === 'id') return gid('Repository', repo.id);
    if (field.name === 'databaseId') return repo.id;
    if (field.name === 'name') return repo.name;
    if (field.name === 'nameWithOwner') return `${repo.owner}/${repo.name}`;
    if (field.name === 'owner') return { __type: 'User', login: repo.owner, id: repo.owner === VIEWER_LOGIN ? VIEWER_ID : 1001, name: repo.owner, email: null };
    if (field.name === 'defaultBranchRef') {
      const tip = branchTip(repo, repo.defaultBranch);
      return tip ? { __type: 'Ref', name: repo.defaultBranch } : null;
    }
    if (field.name === 'viewerPermission') return 'ADMIN';
    if (field.name === 'hasIssuesEnabled') return true;
    if (field.name === 'description') return repo.description;
    if (field.name === 'createdAt' || field.name === 'updatedAt') return isoTs(repo.seq);
    if (field.name === 'url') return `https://github.com/${repo.owner}/${repo.name}`;
    if (field.name === 'issue') {
      const n = typeof args.number === 'number' ? args.number : null;
      if (n === null) return null;
      const issue = repo.issues.get(n);
      return issue ? issueObj(repo, issue) : null;
    }
    if (field.name === 'issues') return issuesConnection(repo, args);
    if (field.name === 'pullRequest') {
      const n = typeof args.number === 'number' ? args.number : null;
      if (n === null) return null;
      const pull = repo.pulls.get(n);
      return pull ? pullObj(repo, pull) : null;
    }
    if (field.name === 'pullRequests') return pullsConnection(repo, args);
    return null;
  }

  if (typeName === 'Issue') {
    const issue = obj.issue as Issue;
    const repo = obj.repo as Repo;
    if (field.name === 'id') return gid('Issue', issue.id);
    if (field.name === 'databaseId') return issue.id;
    if (field.name === 'number') return issue.number;
    if (field.name === 'title') return issue.title;
    if (field.name === 'body') return issue.body;
    if (field.name === 'state') return issue.state.toUpperCase();
    if (field.name === 'createdAt' || field.name === 'updatedAt') return isoTs(issue.seq);
    if (field.name === 'closedAt') return issue.state === 'closed' ? isoTs(issue.seq) : null;
    if (field.name === 'author') return viewerObj();
    if (field.name === 'url') return `https://github.com/${repo.owner}/${repo.name}/issues/${issue.number}`;
    if (field.name === 'labels') {
      const nodes = issue.labels.map((l) => ({ __type: 'Label', id: gid('Label', 1), name: l, color: repo.labels.get(l)?.color ?? 'ededed', description: null }));
      return { __type: 'LabelConnection', nodes, edges: nodes.map((n) => ({ __type: 'LabelEdge', node: n, cursor: '' })), totalCount: nodes.length, pageInfo: { __type: 'PageInfo', hasNextPage: false, hasPreviousPage: false, startCursor: null, endCursor: null } };
    }
    if (field.name === 'comments') {
      const nodes = issue.comments.map((c) => ({ __type: 'Comment', id: c.id, body: c.body, repo, issue }));
      return { __type: 'CommentConnection', nodes, edges: nodes.map((n) => ({ __type: 'CommentEdge', node: n, cursor: '' })), totalCount: nodes.length, pageInfo: { __type: 'PageInfo', hasNextPage: false, hasPreviousPage: false, startCursor: null, endCursor: null } };
    }
    return null;
  }

  if (typeName === 'PullRequest') {
    const pull = obj.pull as Pull;
    const repo = obj.repo as Repo;
    if (field.name === 'id') return gid('PullRequest', pull.id);
    if (field.name === 'databaseId') return pull.id;
    if (field.name === 'number') return pull.number;
    if (field.name === 'title') return pull.title;
    if (field.name === 'body') return pull.body;
    if (field.name === 'state') return pull.state.toUpperCase();
    if (field.name === 'merged') return pull.merged;
    if (field.name === 'mergeable') return pullConflicts(repo, pull) ? 'CONFLICTING' : 'MERGEABLE';
    if (field.name === 'headRefName') return pull.headRef;
    if (field.name === 'baseRefName') return pull.baseRef;
    if (field.name === 'headRef') return { __type: 'Ref', name: pull.headRef };
    if (field.name === 'baseRef') return { __type: 'Ref', name: pull.baseRef };
    if (field.name === 'files') return filesConnection(repo, pull, args);
    if (field.name === 'mergedAt') return pull.mergedAt;
    if (field.name === 'createdAt' || field.name === 'updatedAt') return isoTs(pull.seq);
    if (field.name === 'author') return viewerObj();
    return null;
  }

  if (typeName === 'Ref') {
    if (field.name === 'name') return obj.name ?? null;
    if (field.name === 'target') return null;
    return null;
  }

  if (
    typeName === 'IssueConnection' || typeName === 'PullRequestConnection' || typeName === 'ChangedFileConnection' ||
    typeName === 'LabelConnection' || typeName === 'CommentConnection'
  ) {
    if (field.name === 'nodes') return obj.nodes ?? [];
    if (field.name === 'edges') return obj.edges ?? [];
    if (field.name === 'totalCount') return obj.totalCount ?? 0;
    if (field.name === 'pageInfo') return obj.pageInfo ?? null;
    return null;
  }

  if (
    typeName === 'IssueEdge' || typeName === 'PullRequestEdge' || typeName === 'ChangedFileEdge' ||
    typeName === 'LabelEdge' || typeName === 'CommentEdge'
  ) {
    if (field.name === 'node') return obj.node ?? null;
    if (field.name === 'cursor') return obj.cursor ?? '';
    return null;
  }

  if (typeName === 'ChangedFile') {
    if (field.name === 'path') return obj.path ?? null;
    if (field.name === 'filename') return obj.filename ?? null;
    if (field.name === 'additions') return obj.additions ?? 0;
    if (field.name === 'deletions') return obj.deletions ?? 0;
    if (field.name === 'changes') return obj.changes ?? 0;
    if (field.name === 'status') return obj.status ?? null;
    return null;
  }

  if (typeName === 'Label') {
    if (field.name === 'id') return obj.id ?? null;
    if (field.name === 'name') return obj.name ?? null;
    if (field.name === 'color') return obj.color ?? null;
    if (field.name === 'description') return obj.description ?? null;
    return null;
  }

  if (typeName === 'PageInfo') {
    if (field.name === 'hasNextPage') return obj.hasNextPage ?? false;
    if (field.name === 'hasPreviousPage') return obj.hasPreviousPage ?? false;
    if (field.name === 'startCursor') return obj.startCursor ?? null;
    if (field.name === 'endCursor') return obj.endCursor ?? null;
    return null;
  }

  if (typeName === 'Comment') {
    if (field.name === 'id') return gid('Comment', Number(obj.id ?? 0));
    if (field.name === 'databaseId') return Number(obj.id ?? 0);
    if (field.name === 'body') return obj.body ?? null;
    if (field.name === 'createdAt') return isoTs(0);
    if (field.name === 'author') return viewerObj();
    if (field.name === 'url') return null;
    return null;
  }

  if (
    typeName === 'CreateIssuePayload' || typeName === 'CloseIssuePayload'
  ) {
    if (field.name === 'issue') return obj.issue ?? null;
    if (field.name === 'clientMutationId') return null;
    return null;
  }
  if (typeName === 'CreatePullRequestPayload' || typeName === 'MergePullRequestPayload') {
    if (field.name === 'pullRequest') return obj.pullRequest ?? null;
    if (field.name === 'clientMutationId') return null;
    return null;
  }
  if (typeName === 'AddCommentPayload') {
    if (field.name === 'commentEdge') return obj.commentEdge ?? null;
    if (field.name === 'comment') return obj.comment ?? null;
    if (field.name === 'clientMutationId') return null;
    return null;
  }

  if (typeName === '__Type') {
    if (field.name === 'name') return obj.name ?? null;
    if (field.name === 'kind') return obj.kind ?? null;
    if (field.name === 'description') return obj.description ?? null;
    if (field.name === 'fields') return obj.fields ?? null;
    if (field.name === 'enumValues') return obj.enumValues ?? null;
    if (field.name === 'possibleTypes') return obj.possibleTypes ?? null;
    if (field.name === 'inputFields') return obj.inputFields ?? null;
    return null;
  }
  if (typeName === '__Field') {
    if (field.name === 'name') return obj.name ?? null;
    if (field.name === 'description') return obj.description ?? null;
    if (field.name === 'args') return obj.args ?? [];
    if (field.name === 'type') return obj.type ?? null;
    return null;
  }
  if (typeName === '__EnumValue') {
    if (field.name === 'name') return obj.name ?? null;
    if (field.name === 'description') return obj.description ?? null;
    return null;
  }
  if (typeName === '__InputValue') {
    if (field.name === 'name') return obj.name ?? null;
    if (field.name === 'description') return obj.description ?? null;
    if (field.name === 'type') return obj.type ?? null;
    if (field.name === 'defaultValue') return obj.defaultValue ?? null;
    return null;
  }
  if (typeName === '__Schema') {
    if (field.name === 'queryType') return obj.queryType ?? null;
    if (field.name === 'mutationType') return obj.mutationType ?? null;
    if (field.name === 'types') return obj.types ?? [];
    if (field.name === 'directives') return obj.directives ?? [];
    return null;
  }

  return null;
}

function applySelections(value: unknown, sels: GqlSel[] | undefined, ctx: GqlExecCtx): unknown {
  if (value === null || value === undefined) return value;
  if (Array.isArray(value)) return value.map((v) => applySelections(v, sels, ctx));
  if (typeof value === 'object') {
    const rec = value as Record<string, unknown>;
    if (typeof rec.__type === 'string' && sels) return executeSelections(rec.__type, rec, sels, ctx);
  }
  return value;
}

function executeSelections(typeName: string, obj: Record<string, unknown>, sels: GqlSel[], ctx: GqlExecCtx): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  const allowed = GQL_FIELDS[typeName];
  for (const sel of sels) {
    if (sel.kind === 'spread') {
      const frag = ctx.frags.get(sel.name);
      if (!frag) {
        ctx.errors.push({ message: `Unknown fragment "${sel.name}".` });
        continue;
      }
      if (frag.typeCond && frag.typeCond !== typeName) continue;
      Object.assign(out, executeSelections(typeName, obj, frag.selections, ctx));
      continue;
    }
    if (sel.kind === 'inline') {
      if (sel.typeCond && sel.typeCond !== typeName) continue;
      Object.assign(out, executeSelections(typeName, obj, sel.selections, ctx));
      continue;
    }
    const key = sel.alias ?? sel.name;
    if (allowed && !allowed.has(sel.name)) {
      ctx.errors.push({ message: `Cannot query field "${sel.name}" on type "${typeName}".` });
      out[key] = null;
      continue;
    }
    const value = resolveField(typeName, obj, sel, ctx);
    out[key] = applySelections(value, sel.selections, ctx);
  }
  return out;
}

function runGraphQLOp(doc: { ops: GqlOp[]; frags: Map<string, GqlFrag> }, input: Record<string, unknown>): Record<string, unknown> {
  const errors: Array<Record<string, unknown>> = [];
  const query = input.query;
  if (typeof query !== 'string' || query.trim() === '') {
    return { errors: [{ message: 'Must provide query string.' }] };
  }
  let parsed: { ops: GqlOp[]; frags: Map<string, GqlFrag> };
  try {
    parsed = new GqlParser(gqlLex(query)).parseDocument();
  } catch (e) {
    return { errors: [{ message: e instanceof Error ? e.message : 'Syntax Error' }] };
  }
  void doc;
  let op: GqlOp | undefined = parsed.ops[0];
  const opName = input.operationName;
  if (typeof opName === 'string' && opName !== '') {
    op = parsed.ops.find((o) => o.name === opName) ?? op;
  }
  if (!op) return { errors: [{ message: 'No operation provided.' }] };
  const variables: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(op.varDefs)) variables[k] = v;
  const inputVars = input.variables;
  if (inputVars !== null && typeof inputVars === 'object') {
    for (const [k, v] of Object.entries(inputVars as Record<string, unknown>)) variables[k] = v;
  }
  const ctx: GqlExecCtx = { errors, frags: parsed.frags, variables };
  const rootType = op.kind === 'mutation' ? 'Mutation' : 'Query';
  const data = executeSelections(rootType, {}, op.selections, ctx);
  const result: Record<string, unknown> = { data };
  if (errors.length > 0) result.errors = errors;
  return result;
}

async function handleGraphQL(ctx: Ctx, body: Buffer): Promise<void> {
  let input: unknown;
  try {
    input = parseJsonBody(body);
  } catch {
    return sendJson(ctx, 400, { errors: [{ message: 'Problems parsing JSON' }] });
  }
  if (Array.isArray(input)) {
    const results = input.map((item) =>
      item !== null && typeof item === 'object' ? runGraphQLOp({ ops: [], frags: new Map() }, item as Record<string, unknown>) : { errors: [{ message: 'Invalid operation.' }] },
    );
    return sendJson(ctx, 200, results);
  }
  if (input !== null && typeof input === 'object') {
    return sendJson(ctx, 200, runGraphQLOp({ ops: [], frags: new Map() }, input as Record<string, unknown>));
  }
  return sendJson(ctx, 400, { errors: [{ message: 'Must provide query string.' }] });
}

// ---------------------------------------------------------------- mcp

const MCP_TOOLS: Array<Record<string, unknown>> = [
  {
    name: 'create_repo',
    description: 'Create a new repository owned by the authenticated user.',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'Repository name' },
        description: { type: 'string', description: 'Repository description' },
        private: { type: 'boolean', description: 'Whether the repository is private' },
      },
      required: ['name'],
    },
  },
  {
    name: 'get_repo',
    description: 'Get a repository by owner and name.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'create_issue',
    description: 'Create an issue in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        title: { type: 'string', description: 'Issue title' },
        body: { type: 'string', description: 'Issue body' },
      },
      required: ['owner', 'repo', 'title'],
    },
  },
  {
    name: 'list_issues',
    description: 'List issues in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        state: { type: 'string', description: 'Issue state: open, closed, or all' },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'create_pull_request',
    description: 'Create a pull request in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        title: { type: 'string', description: 'Pull request title' },
        head: { type: 'string', description: 'Head branch name' },
        base: { type: 'string', description: 'Base branch name' },
        body: { type: 'string', description: 'Pull request body' },
      },
      required: ['owner', 'repo', 'title', 'head', 'base'],
    },
  },
  {
    name: 'merge_pull_request',
    description: 'Merge a pull request in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Repository owner login' },
        repo: { type: 'string', description: 'Repository name' },
        pull_number: { type: 'integer', description: 'Pull request number' },
      },
      required: ['owner', 'repo', 'pull_number'],
    },
  },
];

function mcpResult(id: unknown, result: unknown): Record<string, unknown> {
  return { jsonrpc: '2.0', id: id ?? null, result };
}
function mcpError(id: unknown, code: number, message: string): Record<string, unknown> {
  return { jsonrpc: '2.0', id: id ?? null, error: { code, message } };
}
function mcpToolText(obj: unknown): Record<string, unknown> {
  return { content: [{ type: 'text', text: JSON.stringify(obj) }], structuredContent: obj };
}
function mcpToolErr(message: string): Record<string, unknown> {
  return { content: [{ type: 'text', text: message }], isError: true, structuredContent: { message } };
}

function mcpArg(args: Record<string, unknown>, ...names: string[]): unknown {
  for (const n of names) if (args[n] !== undefined) return args[n];
  return undefined;
}

function mcpCallTool(name: string, args: Record<string, unknown>): Record<string, unknown> {
  // Resolve owner/repo, accepting synonyms and full_name.
  let owner = mcpArg(args, 'owner', 'owner_login') as string | undefined;
  let repoName = mcpArg(args, 'repo', 'repository') as string | undefined;
  const fullName = mcpArg(args, 'full_name') as string | undefined;
  if ((!owner || !repoName) && typeof fullName === 'string' && fullName.includes('/')) {
    const [o, r] = fullName.split('/');
    owner = owner ?? o;
    repoName = repoName ?? r;
  }

  if (name === 'create_repo') {
    const repoNameArg = mcpArg(args, 'name') as string | undefined;
    if (typeof repoNameArg !== 'string' || repoNameArg === '') return mcpToolErr('name is required');
    if (getRepo(VIEWER_LOGIN, repoNameArg)) return mcpToolErr(`Repository ${VIEWER_LOGIN}/${repoNameArg} already exists`);
    const repo = createRepo(
      VIEWER_LOGIN,
      repoNameArg,
      mcpArg(args, 'private') === true,
      typeof mcpArg(args, 'description') === 'string' ? (mcpArg(args, 'description') as string) : '',
    );
    return mcpToolText(repoJson(repo));
  }

  if (!owner || !repoName) return mcpToolErr('owner and repo are required');
  const repo = getRepo(owner, repoName);
  if (!repo) return mcpToolErr('Not Found');

  if (name === 'get_repo') {
    return mcpToolText(repoJson(repo));
  }
  if (name === 'create_issue') {
    const title = mcpArg(args, 'title') as string | undefined;
    if (typeof title !== 'string' || title === '') return mcpToolErr('title is required');
    const issue = createIssueGql(repo, title, typeof mcpArg(args, 'body', 'description') === 'string' ? (mcpArg(args, 'body', 'description') as string) : '');
    return mcpToolText(issueJson(repo, issue));
  }
  if (name === 'list_issues') {
    const state = mcpArg(args, 'state') as string | undefined;
    let list = [...repo.issues.values()].sort((a, b) => b.seq - a.seq);
    if (state === 'open') list = list.filter((i) => i.state === 'open');
    else if (state === 'closed') list = list.filter((i) => i.state === 'closed');
    return mcpToolText({ issues: list.map((i) => issueJson(repo, i)) });
  }
  if (name === 'create_pull_request') {
    const title = mcpArg(args, 'title') as string | undefined;
    const head = mcpArg(args, 'head', 'head_ref') as string | undefined;
    const base = mcpArg(args, 'base', 'base_ref') as string | undefined;
    if (typeof title !== 'string' || title === '' || typeof head !== 'string' || head === '' || typeof base !== 'string' || base === '') {
      return mcpToolErr('title, head and base are required');
    }
    const pull = createPullGql(repo, title, head, base);
    if (!pull) return mcpToolErr('Validation Failed: head or base branch does not exist');
    return mcpToolText(pullJson(repo, pull));
  }
  if (name === 'merge_pull_request') {
    const num = mcpArg(args, 'pull_number', 'number');
    const n = typeof num === 'number' ? num : Number(num);
    if (!Number.isInteger(n) || n <= 0) return mcpToolErr('pull_number is required');
    const pull = repo.pulls.get(n);
    if (!pull) return mcpToolErr('Not Found');
    if (pull.state !== 'open') return mcpToolErr('Pull request is already closed');
    if (pullConflicts(repo, pull)) return mcpToolErr('Merge conflict: the pull request cannot be merged');
    mergePullRequest(repo, pull);
    return mcpToolText(pullJson(repo, pull));
  }
  return mcpToolErr(`Unknown tool: ${name}`);
}

async function handleMcp(ctx: Ctx, body: Buffer): Promise<void> {
  let input: unknown;
  try {
    input = parseJsonBody(body);
  } catch {
    return sendJson(ctx, 400, { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
  }
  if (input === null || typeof input !== 'object' || Array.isArray(input)) {
    return sendJson(ctx, 400, { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
  }
  const req = input as Record<string, unknown>;
  const method = typeof req.method === 'string' ? req.method : '';
  const id = req.id === undefined ? null : req.id;
  const params = (req.params !== null && typeof req.params === 'object' ? req.params : {}) as Record<string, unknown>;

  // Notifications (no id) get a 202 with an empty body.
  if (req.id === undefined) {
    return sendRaw(ctx, 202, Buffer.alloc(0), 'application/json');
  }

  if (method === 'server/discover') {
    return sendJson(ctx, 200, mcpResult(id, {
      supportedVersions: ['2026-07-28', '2025-11-25', '2025-06-18'],
      capabilities: { tools: {} },
      serverInfo: { name: 'github-forge-v3', version: VERSION },
    }));
  }
  if (method === 'initialize') {
    const offered = typeof params.protocolVersion === 'string' ? params.protocolVersion : '';
    const versions = ['2026-07-28', '2025-11-25', '2025-06-18'];
    const version = versions.includes(offered) ? offered : '2025-11-25';
    return sendJson(ctx, 200, mcpResult(id, {
      protocolVersion: version,
      capabilities: { tools: {} },
      serverInfo: { name: 'github-forge-v3', version: VERSION },
    }));
  }
  if (method === 'ping') {
    return sendJson(ctx, 200, mcpResult(id, {}));
  }
  if (method === 'tools/list') {
    return sendJson(ctx, 200, mcpResult(id, { tools: MCP_TOOLS }));
  }
  if (method === 'tools/call') {
    const toolName = typeof params.name === 'string' ? params.name : '';
    const toolArgs = (params.arguments !== null && typeof params.arguments === 'object' ? params.arguments : {}) as Record<string, unknown>;
    const known = MCP_TOOLS.some((t) => t.name === toolName);
    if (!known) return sendJson(ctx, 200, mcpError(id, -32602, `Unknown tool: ${toolName}`));
    const result = mcpCallTool(toolName, toolArgs);
    return sendJson(ctx, 200, mcpResult(id, result));
  }
  return sendJson(ctx, 200, mcpError(id, -32601, `Method not found: ${method}`));
}

// ---------------------------------------------------------------- http dispatcher

async function handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const url = new URL(req.url ?? '/', 'http://localhost');
  const ctx: Ctx = {
    req,
    res,
    method: req.method ?? 'GET',
    path: url.pathname,
    query: url.searchParams,
    id: requestId(),
    segments: url.pathname.split('/').filter((s) => s !== ''),
  };
  try {
    if (ctx.path === '/healthz') {
      return sendRaw(ctx, 200, Buffer.from('ok'), 'text/plain');
    }
    if (!authed(ctx)) {
      return sendErr(ctx, 401, 'Unauthorized');
    }
    const body = await readBody(req);
    if (ctx.path === '/api/graphql') {
      return handleGraphQL(ctx, body);
    }
    if (ctx.path === '/mcp') {
      return handleMcp(ctx, body);
    }
    if (ctx.path === '/api/v3' || ctx.path.startsWith('/api/v3/')) {
      return handleRest(ctx, body);
    }
    if (/^\/[^/]+\/[^/]+\.git(\/.*)?$/.test(ctx.path)) {
      return handleGit(ctx, body);
    }
    return sendErr(ctx, 404, 'Not Found');
  } catch (e) {
    if (!res.writableEnded) {
      try {
        sendErr(ctx, 500, 'Internal Server Error');
      } catch {
        // The socket is already gone; nothing more to do.
      }
    }
    void e;
  }
}

// ---------------------------------------------------------------- lifecycle

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

async function main(): Promise<void> {
  const server = createServer((req, res) => {
    void handleRequest(req, res);
  });
  await new Promise<void>((resolve) => server.listen(0, () => resolve()));
  const addr = server.address();
  const port = typeof addr === 'object' && addr !== null ? addr.port : 0;
  if (!ENV_URL) {
    // Local testing: serve forever without the trial environment.
    return;
  }
  try {
    await fetch(`${ENV_URL}/register`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ port }),
    });
  } catch {
    // Registration failure is fatal in the trial; keep polling anyway.
  }
  for (;;) {
    try {
      const r = await fetch(`${ENV_URL}/done`);
      if (r.ok) {
        const j = (await r.json()) as Record<string, unknown>;
        if (j.done === true) break;
      }
    } catch {
      // Transient; retry.
    }
    await sleep(500);
  }
  server.close();
  process.exit(0);
}

void main();








