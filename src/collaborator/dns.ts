// Just enough DNS (RFC 1035) to be the authoritative server for the collaborator
// zone: read the first question of a query, and answer it. Every name under the
// zone resolves to the listener's own address, so a target that looks up a token
// both leaves a DNS hit and can go on to make the HTTP request.

export type DnsQuestion = { id: number; name: string; type: number; questionEnd: number };

const HEADER_LENGTH = 12;
const TYPE_A = 1;
const CLASS_IN = 1;

// Returns null for anything that is not a well-formed single-question query. Name
// compression is not legal in a question from a resolver, so a pointer is refused.
export function parseDnsQuestion(packet: Buffer): DnsQuestion | null {
  if (packet.length < HEADER_LENGTH + 5) return null;
  if (packet.readUInt16BE(4) < 1) return null; // QDCOUNT
  const labels: string[] = [];
  let offset = HEADER_LENGTH;
  for (;;) {
    const length = packet[offset];
    if (length === undefined || length > 63) return null;
    offset += 1;
    if (length === 0) break;
    if (offset + length > packet.length) return null;
    labels.push(packet.toString('latin1', offset, offset + length));
    offset += length;
  }
  if (offset + 4 > packet.length) return null;
  return {
    id: packet.readUInt16BE(0),
    name: labels.join('.'),
    type: packet.readUInt16BE(offset),
    questionEnd: offset + 4,
  };
}

const RCODE_REFUSED = 5;

export function isIpv4Address(value: string): boolean {
  const octets = value.split('.');
  return octets.length === 4 && octets.every((o) => /^\d{1,3}$/.test(o) && Number(o) <= 255);
}

// The listener's whole DNS behaviour for one inbound packet. Null (send nothing) for
// anything that is not a standard query: a response (QR=1) or another opcode, so two
// responders can never bounce answers back and forth. REFUSED, non-authoritative,
// for a name outside the zone, so the listener is never an authority for, or a
// reflector of, someone else's names. Otherwise the authoritative answer.
export function respondToDns(packet: Buffer, baseDomain: string, address: string): Buffer | null {
  const question = parseDnsQuestion(packet);
  if (question === null) return null;
  const flags = packet.readUInt16BE(2);
  const isResponse = (flags & 0x8000) !== 0;
  const opcode = (flags >> 11) & 0x0f;
  if (isResponse || opcode !== 0) return null;

  const name = question.name.toLowerCase();
  const zone = baseDomain.toLowerCase();
  if (name === zone || name.endsWith(`.${zone}`)) return buildDnsAnswer(packet, question, address);

  const header = Buffer.alloc(HEADER_LENGTH);
  header.writeUInt16BE(question.id, 0);
  header.writeUInt16BE(0x8000 | (flags & 0x0100) | RCODE_REFUSED, 2);
  header.writeUInt16BE(1, 4);
  return Buffer.concat([header, packet.subarray(HEADER_LENGTH, question.questionEnd)]);
}

// An authoritative answer (AA) echoing the question. An A query gets one record
// pointing at `address` with TTL 0 (so every lookup of a token reaches us); any
// other type gets NOERROR with no records.
export function buildDnsAnswer(query: Buffer, question: DnsQuestion, address: string): Buffer {
  const header = Buffer.alloc(HEADER_LENGTH);
  header.writeUInt16BE(question.id, 0);
  const recursionDesired = query.readUInt16BE(2) & 0x0100;
  header.writeUInt16BE(0x8000 | 0x0400 | recursionDesired, 2); // QR, AA, RD; RCODE 0
  header.writeUInt16BE(1, 4); // QDCOUNT
  const answers = question.type === TYPE_A ? 1 : 0;
  header.writeUInt16BE(answers, 6); // ANCOUNT
  const questionSection = query.subarray(HEADER_LENGTH, question.questionEnd);
  if (answers === 0) return Buffer.concat([header, questionSection]);

  const record = Buffer.alloc(16);
  record.writeUInt16BE(0xc000 | HEADER_LENGTH, 0); // name: pointer to the question
  record.writeUInt16BE(TYPE_A, 2);
  record.writeUInt16BE(CLASS_IN, 4);
  record.writeUInt32BE(0, 6); // TTL
  record.writeUInt16BE(4, 10);
  address.split('.').forEach((octet, i) => record.writeUInt8(Number(octet), 12 + i));
  return Buffer.concat([header, questionSection, record]);
}
