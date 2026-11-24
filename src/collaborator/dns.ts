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
