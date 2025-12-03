import { z } from "zod";

//common validators

export const hex = z
    .string()
    .regex(/^[0-9a-f]+$/i, "expected hex string");

export const hex32 = hex.length(64); // 32 bytes = 64 hex (e.g., sha256)
export const hex64 = hex.length(128); // 64 bytes = 128 hex (e.g., ed25519 sig)

export const isoDatetime = z
    .string()
    .datetime({ offset: true, message: "expected ISO-8601 timestamp with timezone (e.g., 2025-01-01T00:00:00Z)" });

export const urlStr = z.string().url();

//parties

export const Party = z.object({
    id: z.string().min(1),
    name: z.string().min(1),
});

export type Party = z.infer<typeof Party>;

export const RecordRef = z.object({
    id: z.string().min(1),
    type: z.string().min(1), // Diagnosis | Prescription | TestResult | ...
});
export type RecordRef = z.infer<typeof RecordRef>;


/* ---------------------------------- user ----------------------------------- */
/* On-chain user record (registry entry) */
export const UserRole = z.enum(["PATIENT", "DOCTOR", "ADMIN"]);
export type UserRole = z.infer<typeof UserRole>;

export const User = z.object({
    id: z.string().min(1),
    role: UserRole,
    name: z.string().min(1),
    pubKeyHex: hex.length(64), // 32-byte Ed25519 public key (hex)
    hospitalId: z.string().min(1),
    active: z.boolean().default(true),
    createdAt: isoDatetime,
});
export type User = z.infer<typeof User>;

/* ---------------------------------- node ----------------------------------- */

export const Node = z.object({
    nodeId: z.string().min(1),
    orgName: z.string().min(1),
    pubKeyHex: hex.length(64),
    endpoint: urlStr, // e.g., wss://host:port/path
    joinedAt: isoDatetime,
    active: z.boolean().default(false),
});
export type Node = z.infer<typeof Node>;

/* -------------------------------- consent ---------------------------------- */

export const Consent = z.object({
    consentTxId: z.string().min(1),
    patientId: z.string().min(1),
    doctorId: z.string().min(1),
    scope: z.array(z.string().min(1)).min(1), // e.g., ["Prescription", "Diagnosis"]
    expiresAt: isoDatetime,
});
export type Consent = z.infer<typeof Consent>;

/* ------------------------------ tx base/common ----------------------------- */

export const Operation = z.enum(["Add", "Update", "Share"]);
export type Operation = z.infer<typeof Operation>;

const CommonTx = z.object({
    txId: hex32.optional(), // computed post-sign
    hospital: Party, // Hospital ID/Name (required by prompt)
    doctor: Party.nullable().default(null),
    patient: Party.nullable().default(null),
    insurance: Party.nullable().default(null),
    record: RecordRef.nullable().default(null),
    operation: Operation.nullable().default(null),
    prescription: z.string().nullable().default(null),
    amount: z.number().nonnegative().default(0),
    timestamp: isoDatetime,
    payloadHash: hex32.nullable().default(null), // anchors encrypted off-chain payload
    consentRef: z.string().nullable().default(null), // consent tx id when required
    signer: hex.length(64).optional(), // public key (hex)
    sig: hex64.optional(), // signature (hex)
});

/* -------------------------------- tx shapes -------------------------------- */

const RegisterTx = CommonTx.extend({
    type: z.literal("REGISTER"),
    user: User, // admin registers this user
    // doctor/patient/etc may be null in this tx; hospital is still filled.
});

const ConsentGrantTx = CommonTx.extend({
    type: z.literal("CONSENT_GRANT"),
    consent: Consent, // patient-signed
    patient: Party, // ensure patient is present for convenience
});

const RecordTx = CommonTx.extend({
    type: z.literal("RECORD"),
    doctor: Party,
    patient: Party,
    record: RecordRef,
    operation: Operation, // Add | Update | Share
    consentRef: z.string().min(1), // must reference a valid Consent
    // prescription/amount/payloadHash optional at schema level
});

const AccessLogTx = CommonTx.extend({
    type: z.literal("ACCESS_LOG"),
    // Minimal additional structure to keep schema generic.
    access: z.object({
        who: z.string().min(1), // userId or nodeId performing the access
        op: z.enum(["READ", "WRITE"]),
        outcome: z.enum(["ALLOW", "DENY"]),
        reason: z.string().optional(),
        patientId: z.string().optional(),
        recordId: z.string().optional(),
    }),
});

const NodeJoinTx = CommonTx.extend({
    type: z.literal("NODE_JOIN"),
    applicant: Node.omit({ joinedAt: true, active: true }).extend({
        // applicant supplies data pre-join; joinedAt/active set upon inclusion
        endpoint: urlStr,
    }),
    approvals: z
        .array(
            z.object({
                adminId: z.string().min(1),
                sigHex: hex64,
            }),
        )
        .min(1),
});

const StakeAdjustTx = CommonTx.extend({
    type: z.literal("STAKE_ADJUST"),
    targetNodeId: z.string().min(1),
    delta: z.number(), // positive/negative stake change
});

/* ----------------------------- discriminated union ------------------------- */

export const Tx = z.discriminatedUnion("type", [
    RegisterTx,
    ConsentGrantTx,
    RecordTx,
    AccessLogTx,
    NodeJoinTx,
    StakeAdjustTx,
]);
export type Tx = z.infer<typeof Tx>;

/* --------------------------------- block ----------------------------------- */

export const ConsensusData = z.object({
    epoch: z.number().int().nonnegative(),
    proposer: z.string().min(1), // nodeId of proposer
    seed: hex32,
    importance: z.number().nonnegative(),
    proposerSig: hex64,
});

export const Block = z.object({
    height: z.number().int().nonnegative(),
    timestamp: isoDatetime,
    prevHash: hex32.nullable(), // null for genesis
    merkleRoot: hex32,
    consensusData: ConsensusData,
    txs: z.array(Tx).min(0),
    blockHash: hex32.optional(), // computed after header is filled
});
export type Block = z.infer<typeof Block>;

/* ---------------------------- helper validators ---------------------------- */

export function validateTx(input: unknown): Tx {
    return Tx.parse(input);
}

export function validateBlock(input: unknown): Block {
    return Block.parse(input);
}