import 'dotenv/config';
import boltPkg from '@slack/bolt';
import { google as GoogleAPI } from 'googleapis';

const { App } = boltPkg;

/* =========================
   Slack Socket Mode App
========================= */
const app = new App({
  token: process.env.SLACK_BOT_TOKEN,   // xoxb-...
  appToken: process.env.SLACK_APP_TOKEN, // xapp-... (App-Level Token with connections:write)
  socketMode: true,
  processBeforeResponse: true
});

/* =========================
   Env & Config
========================= */
const WATCH_CHANNEL =
  process.env.FORWARD_CHANNEL_ID || process.env.ORDER_EMAIL_CHANNEL_ID || '';

const SHOPIFY_DOMAIN  = process.env.SHOPIFY_DOMAIN;
const SHOPIFY_TOKEN   = process.env.SHOPIFY_ADMIN_TOKEN;
const SHOPIFY_VERSION = process.env.SHOPIFY_API_VERSION || '2025-10';

const TRELLO_KEY   = process.env.TRELLO_KEY;
const TRELLO_TOKEN = process.env.TRELLO_TOKEN;
const TRELLO_BOARD_ID_ENV = process.env.TRELLO_BOARD_ID || '';
const TRELLO_LIST_ID_ENV  = process.env.TRELLO_LIST_ID  || '';
const TRELLO_BOARD_NAME   = process.env.TRELLO_BOARD_NAME || 'Carismo Design';
const TRELLO_LIST_NAME    = process.env.TRELLO_LIST_NAME  || 'Nick To-Do';

/* Gmail config */
const SHOP_FROM_EMAIL     = (process.env.SHOP_FROM_EMAIL || 'shop@carismodesign.com').toLowerCase();
const GMAIL_CLIENT_ID     = process.env.GMAIL_CLIENT_ID;
const GMAIL_CLIENT_SECRET = process.env.GMAIL_CLIENT_SECRET;
const GMAIL_REDIRECT_URI  = process.env.GMAIL_REDIRECT_URI;
const GMAIL_REFRESH_TOKEN = process.env.GMAIL_REFRESH_TOKEN;

/* Disable OAuth HTTP init/callback on the VPS */
const OAUTH_DISABLED = true;


/* =========================
   Constants
========================= */
const ORDER_REGEX_SINGLE = /(C#\d{4,5})/i;     // single capture
const ORDER_REGEX_MULTI  = /C#\d{4,5}/gi;      // global find-all
const MUST_CONTAIN_SINGLE_PHRASE = /\[RESPONSE REQUIRED\]\s+Your\s+Carismo\s+Order/i;

function isDailyReminderString(s) {
  const normalized = (s || '').replace(/[\u2010\u2011\u2012\u2013\u2014\u2212]/g, '-'); // normalize hyphens
  return /daily\s+reminder/i.test(normalized) && /need\s*photo|needphoto/i.test(normalized);
}

// Shopify targets
const CLEAR_TO_NO = 'No';
const TAGS_TO_REMOVE = ['NeedPhotoNoShip', 'NeedsFollowUp_Yes'];
const MF_NEEDS_FOLLOW_UP = { namespace: 'custom', key: '_nc_needs_follow_up_' };
const MF_FOLLOW_UP_NOTES  = { namespace: 'custom', key: 'follow_up_notes' };

/* =========================
   Shopify Admin GraphQL core
========================= */
async function shopifyGQL(query, variables) {
  const url = `https://${SHOPIFY_DOMAIN}/admin/api/${SHOPIFY_VERSION}/graphql.json`;
  const resp = await fetch(url, {
    method: 'POST',
    headers: {
      'X-Shopify-Access-Token': SHOPIFY_TOKEN,
      'Content-Type': 'application/json',
      'Shopify-API-Version': SHOPIFY_VERSION,
    },
    body: JSON.stringify({ query, variables }),
  });
  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`Shopify HTTP ${resp.status}: ${text}`);
  }
  const json = await resp.json();
  if (json.errors?.length) throw new Error(`Shopify GQL errors: ${JSON.stringify(json.errors)}`);
  if (json.data?.errors?.length) throw new Error(`Shopify data.errors: ${JSON.stringify(json.data.errors)}`);
  return json.data;
}

/* =========================
   Shopify Queries & Mutations
========================= */
const ORDER_LOOKUP_GQL = `
  query ($q: String!) {
    orders(first: 1, query: $q) {
      edges {
        node {
          id
          legacyResourceId
          name
          tags
          needsFollowUpMf: metafield(namespace: "custom", key: "_nc_needs_follow_up_") { id value }
          followUpNotesMf: metafield(namespace: "custom", key: "follow_up_notes") { id value }
        }
      }
    }
  }
`;

const METAFIELDS_SET_GQL = `
  mutation metafieldsSet($metafields: [MetafieldsSetInput!]!) {
    metafieldsSet(metafields: $metafields) {
      metafields { key namespace value }
      userErrors { field message }
    }
  }
`;

/* ✅ FIX: use plural metafieldsDelete API */
const METAFIELDS_DELETE_GQL = `
  mutation metafieldsDelete($metafields: [MetafieldIdentifierInput!]!) {
    metafieldsDelete(metafields: $metafields) {
      deletedMetafields { namespace key }
      userErrors { field message }
    }
  }
`;

const TAGS_REMOVE_GQL = `
  mutation tagsRemove($id: ID!, $tags: [String!]!) {
    tagsRemove(id: $id, tags: $tags) {
      node { ... on Order { id tags } }
      userErrors { field message }
    }
  }
`;

const ORDER_NOTE_QUERY_GQL = `
  query ($id: ID!) {
    order(id: $id) {
      id
      note
    }
  }
`;

const ORDER_UPDATE_GQL = `
  mutation orderUpdate($input: OrderInput!) {
    orderUpdate(input: $input) {
      order { id note }
      userErrors { field message }
    }
  }
`;

/* =========================
   Shopify Helpers
========================= */
async function getOrderByName(orderName) {
  const q = `name:'${orderName}' status:any`;
  const data = await shopifyGQL(ORDER_LOOKUP_GQL, { q });
  return data?.orders?.edges?.[0]?.node ?? null;
}

async function setOrderMetafields(orderId, { needsFollowUp }) {
  const metafields = [];
  if (typeof needsFollowUp !== 'undefined') {
    metafields.push({
      ownerId: orderId,
      namespace: MF_NEEDS_FOLLOW_UP.namespace,
      key: MF_NEEDS_FOLLOW_UP.key,
      type: 'single_line_text_field',
      value: String(needsFollowUp),
    });
  }
  if (!metafields.length) return;
  const res = await shopifyGQL(METAFIELDS_SET_GQL, { metafields });
  const errs = res?.metafieldsSet?.userErrors || [];
  if (errs.length) throw new Error(`metafieldsSet errors: ${JSON.stringify(errs)}`);
}

async function deleteMetafieldByKey({ ownerId, namespace, key }) {
  if (!ownerId || !namespace || !key) return;
  const res = await shopifyGQL(METAFIELDS_DELETE_GQL, {
    metafields: [{ ownerId, namespace, key }],
  });
  const errs = res?.metafieldsDelete?.userErrors || [];
  if (errs.length) throw new Error(`metafieldsDelete errors: ${JSON.stringify(errs)}`);
  return res?.metafieldsDelete?.deletedMetafields || [];
}

/* ✅ You can also delete by ID via metafieldsDelete */
async function deleteMetafieldById({ metafieldId }) {
  if (!metafieldId) return;
  const res = await shopifyGQL(METAFIELDS_DELETE_GQL, {
    metafields: [{ id: metafieldId }],
  });
  const errs = res?.metafieldsDelete?.userErrors || [];
  if (errs.length) throw new Error(`metafieldsDelete errors: ${JSON.stringify(errs)}`);
  return res?.metafieldsDelete?.deletedMetafields || [];
}

async function removeOrderTags(orderId, tags) {
  if (!tags?.length) return [];
  const res = await shopifyGQL(TAGS_REMOVE_GQL, { id: orderId, tags });
  const errs = res?.tagsRemove?.userErrors || [];
  if (errs.length) throw new Error(`tagsRemove errors: ${JSON.stringify(errs)}`);
  return res?.tagsRemove?.node?.tags || [];
}

function orderAdminUrl(legacyId) {
  return `https://${SHOPIFY_DOMAIN}/admin/orders/${legacyId}`;
}

/* ✅ Prepend to the Notes box instead of overwriting */
async function prependOrderNote(orderId, newLine) {
  const noteData = await shopifyGQL(ORDER_NOTE_QUERY_GQL, { id: orderId });
  const existingNote = noteData?.order?.note || '';
  const updatedNote = [
    newLine,
    '',
    '',
    '--------',
    '',
    '',
    existingNote
  ].join('\n');

  const res = await shopifyGQL(ORDER_UPDATE_GQL, { input: { id: orderId, note: updatedNote } });
  const errs = res?.orderUpdate?.userErrors || [];
  if (errs.length) throw new Error(`orderUpdate errors: ${JSON.stringify(errs)}`);
  return res?.orderUpdate?.order?.note || '';
}

/* =========================
   Trello helpers
========================= */
async function trelloGET(path) {
  const url = `https://api.trello.com/1${path}${path.includes('?') ? '&' : '?'}key=${TRELLO_KEY}&token=${TRELLO_TOKEN}`;
  const r = await fetch(url);
  if (!r.ok) throw new Error(`Trello GET ${path} -> ${r.status}`);
  return r.json();
}
async function trelloPOST(path, payload) {
  const url = `https://api.trello.com/1${path}?key=${TRELLO_KEY}&token=${TRELLO_TOKEN}`;
  const r = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
  if (!r.ok) throw new Error(`Trello POST ${path} -> ${r.status}`);
  return r.json();
}

let TRELLO_IDS = { boardId: null, listId: null };
async function resolveTrelloIds() {
  if (TRELLO_BOARD_ID_ENV && TRELLO_LIST_ID_ENV) {
    TRELLO_IDS = { boardId: TRELLO_BOARD_ID_ENV, listId: TRELLO_LIST_ID_ENV };
    return TRELLO_IDS;
  }
  const meBoards = await trelloGET('/members/me/boards?fields=name,id&filter=open');
  const board = meBoards.find(b => (b.name || '').trim().toLowerCase() === TRELLO_BOARD_NAME.trim().toLowerCase());
  if (!board) throw new Error(`Trello board not found: ${TRELLO_BOARD_NAME}`);
  const lists = await trelloGET(`/boards/${board.id}/lists?cards=none&filter=open`);
  const list = lists.find(l => (l.name || '').trim().toLowerCase() === TRELLO_LIST_NAME.trim().toLowerCase());
  if (!list) throw new Error(`Trello list not found on board: ${TRELLO_LIST_NAME}`);
  TRELLO_IDS = { boardId: board.id, listId: list.id };
  return TRELLO_IDS;
}

/* =========================
   Slack Email helpers
========================= */
function collectEmailHaystacks(event) {
  const haystacks = [];
  if (event.text) haystacks.push(event.text);

  if (Array.isArray(event.attachments)) {
    for (const a of event.attachments) {
      if (a.title)   haystacks.push(a.title);
      if (a.text)    haystacks.push(a.text);
      if (a.fallback)haystacks.push(a.fallback);
    }
  }

  if (Array.isArray(event.blocks)) {
    for (const b of event.blocks) {
      if ((b.type === 'section' || b.type === 'header') && b.text?.text) {
        haystacks.push(b.text.text);
      }
      if (b.type === 'rich_text') {
        try { haystacks.push(JSON.stringify(b)); } catch {}
      }
    }
  }

  if (Array.isArray(event.files)) {
    for (const f of event.files) {
      if (f.title) haystacks.push(f.title);
      if (f.name)  haystacks.push(f.name);
    }
  }
  if (event.initial_comment?.comment) {
    haystacks.push(event.initial_comment.comment);
  }
  return haystacks.join('\n');
}

function extractSubjectFromSlackEmail(event) {
  const titles = (event.attachments || []).map(a => a.title).filter(Boolean);
  if (titles.length) return titles[0].trim();
  if (event.text) {
    const first = String(event.text).split('\n')[0].trim();
    if (first.toLowerCase().startsWith('subject:')) {
      return first.replace(/^[Ss]ubject:\s*/, '').trim();
    }
    return first;
  }
  return '';
}

// --- Ignore the Daily NeedPhotoNoShip reminder in THIS app ---
const DAILY_NEEDPHOTO_SUBJECT = /^Daily Reminder to Remove NeedPhotoNoShip Tag and Follow-Up Metafields as Needed$/i;
function isDailyNeedPhotoReminder(event) {
  const subj = extractSubjectFromSlackEmail(event) || '';
  // Fast path by subject; fallback to the loose body check if needed
  if (DAILY_NEEDPHOTO_SUBJECT.test(subj)) return true;

  // (Optional) belt-and-suspenders: use the existing loose detector on the body
  const hay = collectEmailHaystacks(event);
  return isDailyReminderString(hay);
}

/* Download attached file text (Slack Email posts bodies as files in file_share) */
async function slurpSlackFilesText(event, logger) {
  const out = [];
  if (!Array.isArray(event.files) || !event.files.length) return out;

  for (const f of event.files) {
    const url = f.url_private_download || f.url_private;
    if (!url) continue;
    try {
      const r = await fetch(url, {
        headers: { Authorization: `Bearer ${process.env.SLACK_BOT_TOKEN}` },
      });
      if (!r.ok) {
        logger?.warn?.('file fetch failed', { status: r.status, name: f.name, mimetype: f.mimetype });
        continue;
      }
      const text = await r.text();
      out.push(text);
      logger?.info?.({ fileFetched: { name: f.name, size: (text || '').length, mimetype: f.mimetype } });
    } catch (e) {
      logger?.error?.('file fetch error', e);
    }
  }
  return out;
}

// Existing single-order detector (unchanged)
function extractOrderNameFromSingleReply(event) {
  const joined = collectEmailHaystacks(event);
  if (!MUST_CONTAIN_SINGLE_PHRASE.test(joined)) return null;
  const m = joined.match(ORDER_REGEX_SINGLE);
  if (!m) return null;
  return m[1].toUpperCase();
}

// Multi-order detector
async function extractOrderNamesFromDailyReminder(event, logger) {
  const joinedRaw = collectEmailHaystacks(event);
  const joined = joinedRaw.replace(/[\u2010\u2011\u2012\u2013\u2014\u2212]/g, '-'); // normalize hyphens

  let isDaily = isDailyReminderString(joined);

  let corpus = joined;
  let all = corpus.match(ORDER_REGEX_MULTI) || [];

  if (!all.length || !isDaily) {
    const fileTexts = await slurpSlackFilesText(event, logger);
    if (fileTexts.length) {
      corpus += '\n' + fileTexts.join('\n');
      if (!isDaily) isDaily = isDailyReminderString(corpus);
      all = corpus.match(ORDER_REGEX_MULTI) || [];
    }
  }

  logger?.info?.({
    dailyCheck: {
      isDaily,
      foundOrders: all.length,
      snippet: corpus.slice(0, 200)
    }
  });

  if (!isDaily) return [];
  if (!all.length) return [];

  const seen = new Set();
  const deduped = [];
  for (const o of all) {
    const up = o.toUpperCase();
    if (!seen.has(up)) {
      seen.add(up);
      deduped.push(up);
    }
  }
  return deduped;
}

/* =========================
   Gmail helpers (HTML-capable)
========================= */
const b64urlEncode = (str) =>
  Buffer.from(str).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');

const b64urlDecode = (str) =>
  Buffer.from(str.replace(/-/g, '+').replace(/_/g, '/') + '=='.slice((2 - str.length * 3) & 3), 'base64').toString('utf8');

function mkOAuthClient() {
  if (!GMAIL_CLIENT_ID || !GMAIL_CLIENT_SECRET || !GMAIL_REDIRECT_URI) {
    throw new Error('Missing Gmail OAuth env: GMAIL_CLIENT_ID/SECRET/REDIRECT_URI');
  }
  return new GoogleAPI.auth.OAuth2(GMAIL_CLIENT_ID, GMAIL_CLIENT_SECRET, GMAIL_REDIRECT_URI);
}

async function getGmail() {
  if (!GMAIL_REFRESH_TOKEN) throw new Error('GMAIL_REFRESH_TOKEN not set');
  const auth = mkOAuthClient();
  auth.setCredentials({ refresh_token: GMAIL_REFRESH_TOKEN });
  return GoogleAPI.gmail({ version: 'v1', auth });
}

function parseEmailAddress(headerVal) {
  const m = String(headerVal || '').match(/<([^>]+)>/);
  if (m) return m[1].toLowerCase();
  const s = String(headerVal || '').trim();
  if (/^[^@\s]+@[^@\s]+$/.test(s)) return s.toLowerCase();
  return '';
}

function parseAddressList(headerVal) {
  // returns array of bare emails
  return String(headerVal || '')
    .split(',')
    .map(s => s.trim())
    .map(s => {
      const m = s.match(/<([^>]+)>/);
      if (m) return m[1].toLowerCase();
      const t = s.replace(/^["']|["']$/g, '');
      return /^[^@\s]+@[^@\s]+$/.test(t) ? t.toLowerCase() : '';
    })
    .filter(Boolean);
}

function pickNonOurAddress(addresses) {
  const our = SHOP_FROM_EMAIL.toLowerCase();
  return (addresses || []).find(a => a !== our) || '';
}

/** Find the correct CUSTOMER thread (avoid picking our "Fwd" thread) */
async function gmailFindThread({ subjectGuess, orderName }) {
  const gmail = await getGmail();
  const our = SHOP_FROM_EMAIL.toLowerCase();

  // Normalize subject for search (strip leading Re:/Fwd:)
  const normSubject = String(subjectGuess || '')
    .replace(/^\s*(re:|fwd?:)\s*/i, '')
    .trim();

  // Build customer-centric queries
  const baseFilters = `to:${our} -from:${our} newer_than:30d`;
  const queries = [];

  if (normSubject && orderName) {
    queries.push(`${baseFilters} subject:"${normSubject.replace(/"/g, '\\"')}" "${orderName}"`);
  }
  if (orderName) queries.push(`${baseFilters} "${orderName}"`);
  if (normSubject) queries.push(`${baseFilters} subject:"${normSubject.replace(/"/g, '\\"')}"`);

  // Helper to check if a thread has a legit inbound-to-us message
  function threadHasInboundToUs(thread) {
    const msgs = thread.messages || [];
    for (let i = msgs.length - 1; i >= 0; i--) {
      const m = msgs[i];
      const headers = Object.fromEntries((m.payload?.headers || []).map(h => [h.name.toLowerCase(), h.value]));
      const from = (headers['from'] || '').toLowerCase();
      const toList = parseAddressList(headers['to'] || '');
      const subj = headers['subject'] || '';

      const fromIsUs = from.includes(`<${our}>`) || from.includes(our) || from.startsWith(our);
      const toIncludesUs = toList.includes(our);

      const anchorOk = MUST_CONTAIN_SINGLE_PHRASE.test(subj);
      if (!fromIsUs && toIncludesUs && anchorOk) return true;   // ideal case (your “[RESPONSE REQUIRED] …”)
      if (!fromIsUs && toIncludesUs) return true;               // otherwise still customer → us
    }
    return false;
  }

  for (const q of queries) {
    // Search threads, not individual messages
    const tl = await gmail.users.threads.list({ userId: 'me', q, maxResults: 10 });
    const threads = tl.data.threads || [];
    for (const t of threads) {
      const thr = await gmail.users.threads.get({
        userId: 'me',
        id: t.id,
        format: 'full'
      });
      if (threadHasInboundToUs(thr.data)) {
        // Return thread id; let downstream pick the anchored/latest message
        return { threadId: thr.data.id };
      }
    }
  }

  return null;
}

/** Fetch the full thread messages (full payloads) */
async function gmailGetThreadFull(threadId) {
  const gmail = await getGmail();
  const thr = await gmail.users.threads.get({
    userId: 'me',
    id: threadId,
    format: 'full'
  });
  return thr.data.messages || [];
}

/** Find the message whose Subject matches our anchor and that was sent TO us; return its customer address */
async function gmailPickCustomerFromAnchoredHeader(threadId) {
  const messages = await gmailGetThreadFull(threadId);
  const our = SHOP_FROM_EMAIL.toLowerCase();

  // Walk newest -> oldest so we reply to the latest matching customer email
  for (let i = messages.length - 1; i >= 0; i--) {
    const m = messages[i];
    const headers = Object.fromEntries((m.payload?.headers || []).map(h => [h.name.toLowerCase(), h.value]));
    const subj = headers['subject'] || '';
    if (!MUST_CONTAIN_SINGLE_PHRASE.test(subj)) continue;

    const toList = parseAddressList(headers['to'] || '');
    const toIncludesUs = toList.includes(our);
    if (!toIncludesUs) continue;

    // Prefer Reply-To; then From. Always exclude our own address.
    const replyToList = parseAddressList(headers['reply-to'] || '');
    const fromList = parseAddressList(headers['from'] || '');

    const chosen =
      replyToList.find(a => a !== our) ||
      fromList.find(a => a !== our) ||
      '';

    if (chosen) {
      // Also return minimal context for quoting
      const rich = extractRichMessage(m);
      return { email: chosen, rich };
    }
  }
  return null;
}

/** helper to extract html/text + headers of a message */
function extractRichMessage(msg) {
  const headers = Object.fromEntries((msg.payload?.headers || []).map(h => [h.name.toLowerCase(), h.value]));

  function walkParts(p) {
    if (!p) return { html: null, text: null };
    if (p.mimeType?.startsWith('multipart/')) {
      let html = null, text = null;
      for (const part of p.parts || []) {
        const r = walkParts(part);
        html = html || r.html;
        text = text || r.text;
      }
      return { html, text };
    } else {
      const data = p.body?.data ? b64urlDecode(p.body.data) : null;
      if (!data) return { html: null, text: null };
      if (p.mimeType === 'text/html') return { html: data, text: null };
      if (p.mimeType === 'text/plain') return { html: null, text: data };
      return { html: null, text: null };
    }
  }

  const best = walkParts(msg.payload);
  const subject = headers['subject'] || '';
  const from = headers['from'] || '';
  const to = headers['to'] || '';
  const date = headers['date'] || '';
  const msgId = headers['message-id'] || '';

  // Robust recipient pick: prefer Reply-To (non-our), else From (non-our)
  const replyToList = parseAddressList(headers['reply-to'] || '');
  const fromList = parseAddressList(from);
  const replyAddress =
    pickNonOurAddress(replyToList) ||
    pickNonOurAddress(fromList) ||
    parseEmailAddress(headers['reply-to'] || '') ||
    parseEmailAddress(from) ||
    '';

  const plainFromHtml = best.html
    ? best.html.replace(/<\/p>/gi, '\n\n').replace(/<br\s*\/?>/gi, '\n').replace(/<[^>]+>/g, '').trim()
    : null;

  return {
    threadId: msg.threadId,
    messageId: msg.id,
    subject,
    from,
    to,
    date,
    bodyHtml: best.html,
    bodyText: best.text || plainFromHtml || '',
    replyAddress,
    refs: { inReplyTo: msgId, references: msgId },
    _raw: msg
  };
}

/** Latest inbound (not from SHOP_FROM_EMAIL) message in the thread */
/** Latest inbound (from customer) message in the thread */
async function gmailGetLatestInboundInThread(threadId) {
  const messages = await gmailGetThreadFull(threadId);
  const our = SHOP_FROM_EMAIL.toLowerCase();

  // Primary: last message NOT from us
  for (let i = messages.length - 1; i >= 0; i--) {
    const m = messages[i];
    const headers = Object.fromEntries((m.payload?.headers || []).map(h => [h.name.toLowerCase(), h.value]));
    const from = (headers['from'] || '').toLowerCase();
    const fromIsUs = from.includes(`<${our}>`) || from.includes(our) || from.startsWith(our);
    if (!fromIsUs) return extractRichMessage(m);
  }
  // Fallback: last message
  return extractRichMessage(messages[messages.length - 1]);
}

/** utils for HTML replies/forwards */
function textToSafeHtml(s) {
  const esc = String(s || '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  return esc.split('\n').map(line => line.trim() ? `<p>${line}</p>` : '<p><br></p>').join('');
}
function quoteOriginalHtml({ date, from, html }) {
  const header = `<div>On ${date}, ${from} wrote:</div>`;
  const quoted = `<blockquote style="margin:0 0 0 .8ex;border-left:1px solid #ccc;padding-left:1ex">${html || '[original message not available]'}</blockquote>`;
  return `${header}${quoted}`;
}

/** fetch attachments (filename, mimeType, base64 data) from a Gmail message */
async function collectAttachmentsFromMessage(msg) {
  const gmail = await getGmail();
  const out = [];

  function walk(parts = []) {
    for (const p of parts) {
      if (p.parts && p.parts.length) walk(p.parts);
      const filename = p.filename || '';
      const attId = p.body?.attachmentId;
      const mime = p.mimeType || 'application/octet-stream';
      if (filename && attId) {
        out.push({ attachmentId: attId, filename, mime });
      }
    }
  }
  walk(msg.payload?.parts || []);

  const files = [];
  for (const meta of out) {
    const res = await gmail.users.messages.attachments.get({
      userId: 'me',
      messageId: msg.id,
      id: meta.attachmentId
    });
    // Gmail returns base64url; convert to standard base64 for MIME
    const dataUrl = res.data.data || '';
    const dataStd = dataUrl.replace(/-/g, '+').replace(/_/g, '/');
    files.push({ filename: meta.filename, mime: meta.mime, b64: dataStd });
  }
  return files;
}

/** build multipart/mixed with alternative + attachments */
function buildRawEmailMixed({ from, to, subject, textBody, htmlBody, attachments = [], inReplyTo, references }) {
  const mixed = 'mix_' + Math.random().toString(36).slice(2);
  const alt = 'alt_' + Math.random().toString(36).slice(2);

  const headers = [
    `From: ${from}`,
    `To: ${to}`,
    `Subject: ${subject}`,
    'MIME-Version: 1.0',
    `Content-Type: multipart/mixed; boundary="${mixed}"`
  ];
  if (inReplyTo) headers.push(`In-Reply-To: ${inReplyTo}`);
  if (references) headers.push(`References: ${references}`);

  const parts = [
    `--${mixed}`,
    `Content-Type: multipart/alternative; boundary="${alt}"`,
    '',
    `--${alt}`,
    'Content-Type: text/plain; charset="UTF-8"',
    'Content-Transfer-Encoding: 7bit',
    '',
    textBody || '',
    `--${alt}`,
    'Content-Type: text/html; charset="UTF-8"',
    'Content-Transfer-Encoding: 7bit',
    '',
    htmlBody || '',
    `--${alt}--`,
    ''
  ];

  for (const att of attachments) {
    parts.push(
      `--${mixed}`,
      `Content-Type: ${att.mime}; name="${att.filename.replace(/"/g, '')}"`,
      'Content-Transfer-Encoding: base64',
      `Content-Disposition: attachment; filename="${att.filename.replace(/"/g, '')}"`,
      '',
      att.b64,
      ''
    );
  }
  parts.push(`--${mixed}--`, '');

  return b64urlEncode(headers.join('\r\n') + '\r\n\r\n' + parts.join('\r\n'));
}

function buildRawEmailAlt({ from, to, subject, textBody, htmlBody, inReplyTo, references }) {
  const boundary = 'b_' + Math.random().toString(36).slice(2);
  const headers = [
    `From: ${from}`,
    `To: ${to}`,
    `Subject: ${subject}`,
    'MIME-Version: 1.0',
    `Content-Type: multipart/alternative; boundary="${boundary}"`
  ];
  if (inReplyTo) headers.push(`In-Reply-To: ${inReplyTo}`);
  if (references) headers.push(`References: ${references}`);

  const parts = [
    `--${boundary}`,
    'Content-Type: text/plain; charset="UTF-8"',
    'Content-Transfer-Encoding: 7bit',
    '',
    textBody || '',
    `--${boundary}`,
    'Content-Type: text/html; charset="UTF-8"',
    'Content-Transfer-Encoding: 7bit',
    '',
    htmlBody || '',
    `--${boundary}--`,
    ''
  ];

  return b64urlEncode(headers.join('\r\n') + '\r\n\r\n' + parts.join('\r\n'));
}

/** (Legacy helpers kept; not used by new HTML flow but safe to keep) */
function buildReplyBodyWithQuote({ replyBody, latest }) {
  const header = `\n\nOn ${latest.date}, ${latest.from} wrote:\n`;
  const quoted = latest.bodyText
    ? latest.bodyText.split('\n').map(l => `> ${l}`).join('\n')
    : '> [original message not available]';
  return `${replyBody}${header}${quoted}`;
}
function buildRawEmail({ from, to, subject, body, inReplyTo, references }) {
  const lines = [
    `From: ${from}`,
    `To: ${to}`,
    `Subject: ${subject}`,
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset="UTF-8"',
    'Content-Transfer-Encoding: 7bit',
  ];
  if (inReplyTo) lines.push(`In-Reply-To: ${inReplyTo}`);
  if (references) lines.push(`References: ${references}`);
  lines.push('', body.endsWith('\n') ? body : body + '\n');
  const rfc822 = lines.join('\r\n');
  return b64urlEncode(rfc822);
}
async function gmailSendReply({ threadId, replyToAddress, subject, inReplyTo, references, body }) {
  const gmail = await getGmail();
  const subj = subject.startsWith('Re:') ? subject : `Re: ${subject}`;
  const raw = buildRawEmail({
    from: SHOP_FROM_EMAIL,
    to: replyToAddress,
    subject: subj,
    body,
    inReplyTo,
    references
  });
  const sent = await gmail.users.messages.send({ userId: 'me', requestBody: { raw, threadId } });
  return sent.data.id;
}

/** Forward inline with HTML preserved */
/** Forward inline with HTML preserved + original attachments */
async function gmailForwardInline({ subject, toList, latest }) {
  const gmail = await getGmail();
  const subj = subject.startsWith('Fwd:') ? subject : `Fwd: ${subject}`;

  // Pull attachments from the original inbound Gmail message
  const attachments = await collectAttachmentsFromMessage(latest._raw);

  const headerBlockHtml = [
    '<div>---------- Forwarded message ----------</div>',
    `<div>From: ${latest.from}</div>`,
    `<div>Date: ${latest.date}</div>`,
    `<div>Subject: ${latest.subject}</div>`,
    `<div>To: ${latest.to}</div>`,
    '<br/>'
  ].join('\n');

  const htmlBody =
    headerBlockHtml +
    (latest.bodyHtml || (latest.bodyText && textToSafeHtml(latest.bodyText)) || '<div>[original message not available]</div>');

  const textBody =
    '---------- Forwarded message ----------\n' +
    `From: ${latest.from}\n` +
    `Date: ${latest.date}\n` +
    `Subject: ${latest.subject}\n` +
    `To: ${latest.to}\n\n` +
    (latest.bodyText || '[original message not available]');

  const raw = buildRawEmailMixed({
    from: SHOP_FROM_EMAIL,
    to: toList.join(', '),
    subject: subj,
    textBody,
    htmlBody,
    attachments
  });

  const sent = await gmail.users.messages.send({ userId: 'me', requestBody: { raw } });
  return sent.data.id;
}

/* =========================
   UI: action card (UPDATED)
========================= */
function actionBlocks({ orderName, preview, subjectGuess }) {
  return [
    { type: 'section', text: { type: 'mrkdwn', text: `New reply detected for *${orderName}*.\nChoose an action:` } },
    preview ? { type: 'context', elements: [{ type: 'mrkdwn', text: `_${preview}_` }] } : null,
    {
      type: 'actions',
      elements: [
        { type: 'button', text: { type: 'plain_text', text: 'Good, clear tags' }, action_id: 'good_clear', style: 'primary', value: JSON.stringify({ orderName, subjectGuess }) },
        { type: 'button', text: { type: 'plain_text', text: 'Reply/Forward' }, action_id: 'reply_forward', value: JSON.stringify({ orderName, subjectGuess }) },
        { type: 'button', text: { type: 'plain_text', text: 'Make Trello Card' }, action_id: 'make_trello', value: JSON.stringify({ orderName, subjectGuess }) }
      ]
    }
  ].filter(Boolean);
}

async function postActionCard({ client, channel, thread_ts, orderName, preview, subjectGuess }) {
  await client.chat.postMessage({
    channel,
    thread_ts,
    text: `Actions for ${orderName}`,
    blocks: actionBlocks({ orderName, preview, subjectGuess })
  });
}

/* =========================
   Slack events
========================= */
app.event('message', async ({ event, client, logger }) => {
  try {
    logger.info({
      msg: 'message event',
      ch: event.channel,
      subtype: event.subtype,
      bot_id: !!event.bot_id,
      hasText: !!event.text,
      hasBlocks: Array.isArray(event.blocks),
      hasFiles: Array.isArray(event.files),
      ts: event.ts
    });

    if (!WATCH_CHANNEL) return;
    if (event.channel !== WATCH_CHANNEL) return;

    // ⛔️ Hard stop: this bot must NOT act on the daily NeedPhotoNoShip reminders
    if (isDailyNeedPhotoReminder(event)) {
      logger.info('Skipping daily NeedPhotoNoShip reminder in oem-email-confirmation bot');
      return;
    }

    // SINGLE-ORDER “[RESPONSE REQUIRED] …”
    const single = extractOrderNameFromSingleReply(event);
    if (single) {
      const preview =
        (event.text && event.text.slice(0, 120)) ||
        (event.files?.[0]?.title?.slice(0, 120)) ||
        '';
      const subjectGuess = extractSubjectFromSlackEmail(event);

      await postActionCard({
        client,
        channel: event.channel,
        thread_ts: event.ts,
        orderName: single,
        preview,
        subjectGuess
      });
      return;
    }

  } catch (e) {
    logger.error('message handler error', e);
  }
});

// Helper to safely show text inside a Slack code block
function _forCodeBlock(s) {
  return String(s ?? '').replace(/```/g, '`​`​`').trim(); // uses zero-width spaces
}

/* =========================
   Slack actions: Good/Clear
========================= */
app.action('good_clear', async ({ ack, body, client, logger }) => {
  await ack();
  const channel = body.channel?.id;
  const thread_ts = body.message?.thread_ts || body.message?.ts;

  let orderName = '';
  try {
    const payload = JSON.parse(body.actions?.[0]?.value || '{}');
    orderName = payload.orderName || '';
  } catch {}

  try {
    const order = await getOrderByName(orderName);
    if (!order) {
      await client.chat.postMessage({ channel, thread_ts, text: `❌ Order not found: ${orderName}` });
      return;
    }

    const orderId  = order.id;
    const legacyId = order.legacyResourceId;

    const oldNeeds = order?.needsFollowUpMf?.value ?? null;
    const oldNotes = order?.followUpNotesMf?.value ?? null;

    // Set needs_follow_up = "No"
    await setOrderMetafields(orderId, { needsFollowUp: CLEAR_TO_NO });

    // Delete follow_up_notes by key
    await deleteMetafieldByKey({
      ownerId: orderId,
      namespace: MF_FOLLOW_UP_NOTES.namespace,
      key: MF_FOLLOW_UP_NOTES.key,
    });

    // Remove tags
    await removeOrderTags(orderId, TAGS_TO_REMOVE);

    // PREPEND to Notes
    const date = new Date().toISOString().slice(0, 10);
    const by = `@${body.user?.username || body.user?.name || 'user'}`;
    const newLine = `Info verified via customer email response on ${date} by ${by}`;
    await prependOrderNote(orderId, newLine);

    const adminUrl = orderAdminUrl(legacyId);

    const oldNotesShown =
      (oldNotes && _forCodeBlock(oldNotes.slice(0, 4000))) || '(blank)';

    const lines = [
      `:white_check_mark: *Updated ${orderName}*`,
      '',

      '• Metafield `custom._nc_needs_follow_up_`:',
      `> ${oldNeeds || '(blank)'} → *No*`,
      '',

      '• Metafield `custom.follow_up_notes` (old → new):',
      '```',
      `${oldNotesShown}`,
      '```',
      '→ `deleted`',
      '',

      '• Tags removed:',
      TAGS_TO_REMOVE.join(', '),
      '',

      '• Note prepended with audit entry',
      '',

      `<${adminUrl}|Open Order in Shopify Admin>`
    ];

    await client.chat.postMessage({ channel, thread_ts, text: lines.join('\n') });

  } catch (e) {
    logger?.error?.('good_clear failed', e);
    await client.chat.postMessage({
      channel, thread_ts,
      text: `❌ Failed to clear tags/metafields: ${e.message}`
    });
  }
});

/* =========================
   Slack actions: Make Trello Card
========================= */
app.action('make_trello', async ({ ack, body, client, logger }) => {
  await ack();
  const channel = body.channel?.id;
  const thread_ts = body.message?.thread_ts || body.message?.ts;

  let orderName = '';
  try {
    const payload = JSON.parse(body.actions?.[0]?.value || '{}');
    orderName = payload.orderName || '';
  } catch {}

  try {
    const { listId } = await resolveTrelloIds();
    const title = `${orderName} needs more info, needs email follow up`;
    const card = await trelloPOST('/cards', { idList: listId, name: title });
    await client.chat.postMessage({
      channel, thread_ts,
      text: `📝 Trello card created: ${card.url}`
    });
  } catch (e) {
    logger?.error?.('make_trello failed', e);
    await client.chat.postMessage({
      channel, thread_ts,
      text: `❌ Failed to create Trello card: ${e.message}`
    });
  }
});

/* =========================
   Slack actions: Reply/Forward
========================= */
app.action('reply_forward', async ({ ack, body, client }) => {
  await ack();

  const channel = body.channel?.id;
  const thread_ts = body.message?.thread_ts || body.message?.ts;

  let orderName = '', subjectGuess = '';
  try {
    const payload = JSON.parse(body.actions?.[0]?.value || '{}');
    orderName = payload.orderName || '';
    subjectGuess = payload.subjectGuess || '';
  } catch {}

  await client.views.open({
    trigger_id: body.trigger_id,
    view: {
      type: 'modal',
      callback_id: 'choose_reply_or_forward',
      title: { type: 'plain_text', text: 'Email Action' },
      submit: { type: 'plain_text', text: 'Next' },
      close: { type: 'plain_text', text: 'Cancel' },
      blocks: [
        { type: 'section', text: { type: 'mrkdwn', text: `*${orderName}* • _${subjectGuess || 'Email'}_` } },
        {
          type: 'input',
          block_id: 'choice_block',
          label: { type: 'plain_text', text: 'What do you want to do?' },
          element: {
            type: 'radio_buttons',
            action_id: 'choice',
            options: [
              { text: { type: 'plain_text', text: 'Reply to Customer' }, value: 'reply' },
              { text: { type: 'plain_text', text: 'Forward to Team' }, value: 'forward' }
            ]
          }
        }
      ],
      private_metadata: JSON.stringify({ channel, thread_ts, orderName, subjectGuess })
    }
  });
});

/* Choose Reply or Forward -> next modal */
app.view('choose_reply_or_forward', async ({ ack, body, view, client }) => {
  const md = JSON.parse(view.private_metadata || '{}');
  const choice = view.state.values?.choice_block?.choice?.selected_option?.value;

  if (!choice) {
    await ack({ response_action: 'errors', errors: { choice_block: 'Select an option' } });
    return;
  }

  await ack({
    response_action: 'update',
    view: choice === 'reply'
      ? {
          type: 'modal',
          callback_id: 'reply_body_modal',
          title: { type: 'plain_text', text: 'Reply to Customer' },
          submit: { type: 'plain_text', text: 'Review' },
          close: { type: 'plain_text', text: 'Cancel' },
          blocks: [
            {
              type: 'input',
              block_id: 'email_block',
              label: { type: 'plain_text', text: 'Customer email (optional)' },
              element: {
                type: 'plain_text_input',
                action_id: 'email',
                placeholder: { type: 'plain_text', text: 'e.g. customer@example.com' }
              },
              optional: true
            },
            {
              type: 'input',
              block_id: 'subj_block',
              label: { type: 'plain_text', text: 'Subject (optional)' },
              element: {
                type: 'plain_text_input',
                action_id: 'subject',
                initial_value: (md.subjectGuess || '')
              },
              optional: true
            },
            {
              type: 'input',
              block_id: 'body_block',
              label: { type: 'plain_text', text: 'Message to customer' },
              element: {
                type: 'plain_text_input',
                action_id: 'body',
                multiline: true,
                placeholder: { type: 'plain_text', text: 'Type your reply…' }
              }
            }
          ],
          private_metadata: JSON.stringify(md)
        }
      : {
          type: 'modal',
          callback_id: 'forward_pick_modal',
          title: { type: 'plain_text', text: 'Forward to Team' },
          submit: { type: 'plain_text', text: 'Review' },
          close: { type: 'plain_text', text: 'Cancel' },
          blocks: [
            {
              type: 'input',
              block_id: 'to_block',
              label: { type: 'plain_text', text: 'Select recipients' },
              element: {
                type: 'multi_static_select',
                action_id: 'to',
                options: [
                  'kenny@carismodesign.com',
                  'kevinl@carismodesign.com',
                  'irish@carismodesign.com',
                  'k@carismodesign.com',
                  'shop@carismodesign.com',
                  'nicholas@carismodesign.com',
                ].map(e => ({ text: { type: 'plain_text', text: e }, value: e })),
                placeholder: { type: 'plain_text', text: 'Pick one or more' }
              }
            }
          ],
          private_metadata: JSON.stringify(md)
        }
  });
});

/* Reply: body -> review */
app.view('reply_body_modal', async ({ ack, body, view, client }) => {
  const md = JSON.parse(view.private_metadata || '{}');
  const replyBody = view.state.values?.body_block?.body?.value?.trim();
  const email = view.state.values?.email_block?.email?.value?.trim();
  const subjectLine = view.state.values?.subj_block?.subject?.value?.trim();

  if (!replyBody) {
    await ack({ response_action: 'errors', errors: { body_block: 'Please enter a message' } });
    return;
  }

  await ack({
    response_action: 'update',
    view: {
      type: 'modal',
      callback_id: 'reply_review_modal',
      title: { type: 'plain_text', text: 'Review Reply' },
      submit: { type: 'plain_text', text: 'Send' },
      close: { type: 'plain_text', text: 'Back' },
        blocks: [
          { type: 'section', text: { type: 'mrkdwn', text: `*To:* ${email || '_(auto-detect at send time_)'}` } },
          { type: 'section', text: { type: 'mrkdwn', text: `*Subject:* ${subjectLine || (md.subjectGuess || '_(will be derived_)')}` } },
          { type: 'section', text: { type: 'mrkdwn', text: '*Your message:*' } },
          { type: 'section', text: { type: 'mrkdwn', text: '```' + replyBody + '```' } }
        ],
            private_metadata: JSON.stringify({ ...md, replyBody, email, subjectLine })
    }
  });
});

/* Reply: send (HTML + latest inbound) */
app.view('reply_review_modal', async ({ ack, body, view, client, logger }) => {
  await ack();

  const md = JSON.parse(view.private_metadata || '{}');
  const { channel, thread_ts, orderName, subjectGuess, replyBody, email: overrideEmail, subjectLine: overrideSubject } = md;

  try {
    const found = await gmailFindThread({ subjectGuess, orderName });
if (!found) throw new Error('Could not locate Gmail thread. Try replying in Gmail for this one.');

// 1) Try the anchored-header heuristic
const anchored = await gmailPickCustomerFromAnchoredHeader(found.threadId);

// 2) Fallback to "latest inbound not from us"
const latest = anchored?.rich || await gmailGetLatestInboundInThread(found.threadId);

// Final reply-to address (anchored wins)
const replyTo = (overrideEmail && overrideEmail.length > 0 ? overrideEmail : (anchored?.email || latest.replyAddress));
if (!replyTo) throw new Error('Could not determine customer email address (Reply-To/From missing) — try entering it in the modal.');

    const subjectBase = (overrideSubject && overrideSubject.length > 0)
  ? overrideSubject
  : (latest.subject || (subjectGuess || `Your Carismo Order ${orderName}`));
const subject = subjectBase.startsWith('Re:') ? subjectBase : `Re: ${subjectBase}`;

    // Build plain + HTML with quoted original HTML to preserve formatting
    const htmlReply = [
      textToSafeHtml(replyBody),
      '<br>',
      quoteOriginalHtml({ date: latest.date, from: latest.from, html: latest.bodyHtml || (latest.bodyText && textToSafeHtml(latest.bodyText)) })
    ].join('\n');

    const textReply = `${replyBody}\n\nOn ${latest.date}, ${latest.from} wrote:\n` +
      (latest.bodyText ? latest.bodyText.split('\n').map(l => `> ${l}`).join('\n') : '> [original message not available]');

    const raw = buildRawEmailAlt({
      from: SHOP_FROM_EMAIL,
      to: replyTo,
      subject,
      textBody: textReply,
      htmlBody: htmlReply,
      inReplyTo: latest.refs.inReplyTo,
      references: latest.refs.references
    });

    const gmail = await getGmail();
    await gmail.users.messages.send({ userId: 'me', requestBody: { raw, threadId: latest.threadId } });

    await client.chat.postMessage({
      channel, thread_ts,
      text: `✉️ Replied to customer (${replyTo}) from *${SHOP_FROM_EMAIL}*.\n_Subject:_ ${subject}`
    });
  } catch (e) {
    logger?.error?.('reply send failed', e);
    await client.chat.postMessage({ channel, thread_ts, text: `❌ Reply failed: ${e.message}` });
  }
});

/* Forward: pick -> review */
app.view('forward_pick_modal', async ({ ack, body, view, client }) => {
  const md = JSON.parse(view.private_metadata || '{}');
  const tos = (view.state.values?.to_block?.to?.selected_options || []).map(o => o.value);

  if (!tos.length) {
    await ack({ response_action: 'errors', errors: { to_block: 'Pick at least one recipient' } });
    return;
  }

  await ack({
    response_action: 'update',
    view: {
      type: 'modal',
      callback_id: 'forward_review_modal',
      title: { type: 'plain_text', text: 'Review Forward' },
      submit: { type: 'plain_text', text: 'Send' },
      close: { type: 'plain_text', text: 'Back' },
      blocks: [
        { type: 'section', text: { type: 'mrkdwn', text: '*Recipients:* ' + tos.join(', ') } }
      ],
      private_metadata: JSON.stringify({ ...md, tos })
    }
  });
});

/* Forward: send (HTML preserved) */
app.view('forward_review_modal', async ({ ack, body, view, client, logger }) => {
  await ack();

  const md = JSON.parse(view.private_metadata || '{}');
  const { channel, thread_ts, orderName, subjectGuess, tos } = md;

  try {
    const found = await gmailFindThread({ subjectGuess, orderName });
if (!found) throw new Error('Could not locate Gmail thread for forward.');

const latest = await gmailGetLatestInboundInThread(found.threadId);

    await gmailForwardInline({
      subject: subjectGuess || latest.subject || `Your Carismo Order ${orderName}`,
      toList: tos,
      latest
    });

    await client.chat.postMessage({
      channel, thread_ts,
      text: `📤 Forwarded from *${SHOP_FROM_EMAIL}* to: ${tos.join(', ')}`
    });
  } catch (e) {
    logger?.error?.('forward send failed', e);
    await client.chat.postMessage({ channel, thread_ts, text: `❌ Forward failed: ${e.message}` });
  }
});

/* =========================
   Start
========================= */
(async () => {
  await app.start(); // ← no port in Socket Mode
  console.log('✅ email-actions bot running (Socket Mode)');
  console.log('🔧 Watching channel ID:', WATCH_CHANNEL || '(not set)');

  try {
    await resolveTrelloIds();
    console.log('✅ Trello board/list resolved');
  } catch (e) {
    console.error('⚠️ Trello board/list resolution failed. Will retry on first use.', e.message);
  }
})();