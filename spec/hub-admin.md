# Sparrow Hub Administration (sparrow.hub.admin v1)

> Companion to the core specification (`core.md`, section 10.9). Snapshot of the live draft, revision 16, exported for this repository. The live document is the source of truth.

A hub that implements this interface can be configured entirely at run time by a controlling application, such as an orchestrator that runs the hub in a container. The controller pushes one desired-state document; the hub validates it, applies it as a whole, and rolls it back by itself unless the controller confirms it in time. A bootstrap administrator can always reach the interface, so no document can lock the hub out of administration.

## 1. The facet

- The hub publishes a facet named `sparrow.hub.admin`, version `1.0.0`, that implements the interface of section 5. Its facet ID is the hub's choice and stays stable (Hub Profile, section 10.3).
- Every method is authorized like any other call (Hub Profile, section 10.4); every method carries the hint annotation `"sparrow.level": "manage"`.
- **Bootstrap administrator:** the hub's static configuration names at least one principal that is always allowed every method of this facet. No configuration document can take that away.
- Authorization policy (who may call what) is hub-specific. It lives in the document's `extensions`, so confirmation and rollback cover it like everything else.

## 2. Configuration model

The hub's configuration is one document with a **revision** number.

- **Revisions** are unsigned integers, persisted with the document, that go up by one each time the applied document changes, rollbacks included. Revision 0 is a hub that has never been configured, with the document `{nodes: {}}`.
- **Commits replace the whole document.** There is no patch format; a controller reads the document, changes it and commits the result against the revision it read.
- **Optimistic concurrency:** a commit names the revision it is based on, and fails with `Error(aborted)` if that is no longer current. When no commit is pending, a commit whose document equals the applied one changes nothing and returns the current revision, whatever its base, so retrying a commit whose reply was lost is safe.
- **Validation first:** a commit is validated as a whole before anything changes (section 3). If any problem is found, it fails with `Error(failed_precondition)`, and nothing changes.
- **Content by reference:** secrets and facet documents are stored separately, cannot be changed once stored, and are referenced from the document by name or hash. The document stays small, and every change to what a node presents goes through a commit, so confirmation and rollback cover it.

### 2.1 Stored secrets and facets

- `setSecret` stores a secret under a new name. A name that already exists fails with `Error(already_exists)`: to rotate a secret, store it under a new name and commit a document that refers to it. No method ever returns a secret's value.
- `putFacet` stores a canonical facet document, valid as in core spec section 6.6 rule 3 with its facet ID ignored and set to 0, and returns its **stored-facet key**: `0x01 || SHA-256` of those canonical bytes, name included. Storing the same facet again returns the same key.
- `deleteSecret` and `deleteFacet` succeed when the item does not exist, and fail with `Error(failed_precondition)` while the applied document or the rollback target of a pending commit refers to it.
- Secret names follow the node-ID grammar (Hub Profile, section 10.2).

### 2.2 Applying a commit

When a commit passes validation, the hub switches to the new document at once and then **reconciles** in the background. `commit` returns after the switch, not after reconciliation; progress is visible in `watch`.

- A node added to the document is started, dialed or accepted when it dials in, as its configuration says.
- A node removed from the document, or disabled, has its session ended with `GoAway(going_away)`; its facets leave every schema through ordinary schema updates. A removed node's facet IDs are retired for good; a disabled node keeps them for when it is enabled again (Hub Profile, section 10.3).
- A spawned node whose start changed is stopped and started again (Hub Profile, section 10.7). A dialed node whose URL, key hash or credential changed is dialed again, and the new session supersedes the old one. A dial-in node whose credential changed has its session closed with `GoAway(unauthenticated)` and must dial in again (Hub Profile, section 10.2).
- Changes to listed facets, defaults and policy reach sessions as ordinary schema updates and authorization changes (Hub Profile, sections 10.3 and 10.4).

### 2.3 Confirmation and rollback

A commit with `confirmWithinMs` greater than 0 is **pending** until it is confirmed:

- At most one commit is pending. While one is, every commit fails with `Error(aborted)`, even one identical to the pending document; the controller reads the outcome with `get` or `watch` and retries later.
- The **rollback target** is the pending commit's base document. Because nothing else can commit meanwhile, it is always the last confirmed document.
- `confirm(N)` succeeds if N is the current revision and is pending or confirmed; otherwise it fails with `Error(not_found)`, which means only that N is no longer current; the controller reads what happened with `get` or `watch`. The hub decides atomically at the deadline, so a confirmation processed after it fails.
- `rollback(N)` rolls a pending revision N back at once.
- **A rollback**, whether from the deadline, from `rollback` or from a restart while a commit is pending, applies the rollback target as revision N+1, already confirmed. `watch` reports `rolledBack` for N, then `confirmed` for N+1.
- A commit with `confirmWithinMs` of 0 is confirmed at once.

A controller SHOULD confirm over a new session, which shows that new connections still work after the change.

### 2.4 Persistence and bootstrap

The hub persists the last confirmed document with its revision, the highest revision number it has handed out, the stored secrets and facets, its facet-ID table and the last known facets of every node (Hub Profile, sections 10.3 and 10.7). It records the high-water mark before `commit` returns, so a revision number is never handed out twice. A pending commit is never persisted as confirmed. The static configuration (listen addresses, TLS settings and the bootstrap administrator) is up to the implementation. Upgrading the hub's program is the job of whatever runs the hub, never of this interface.

## 3. The document

```
Config = {
  nodes:         { * node-id => NodeConfig },
  ? defaults:    { * bstr => facet-name },   ; interface hash => preferred facet
  ? extensions:  { * tstr => bstr }          ; hub-specific settings, each a CBOR document
}

NodeConfig = {
  ? start:       Start,          ; absent: the node dials in
  ? credential:  secret-name,    ; what a dial-in node must present; only without start
  ? facets:      [* bstr],       ; stored-facet keys, listed until the node is first seen
  ? peer:        bool,           ; the node is another hub (Hub Profile, section 10.8)
  ? enabled:     bool,           ; default true
  ? extensions:  { * tstr => bstr }
}

Start    = Spawn / Dial / Other
Spawn    = { command: [+ tstr], ? env: { * tstr => EnvValue }, ? dir: tstr }
EnvValue = [0, tstr]            ; a literal value
         / [1, secret-name]     ; the value of a stored secret
Dial     = { url: tstr, pin: bstr, credential: secret-name }
           ; pin: SHA-256 of the node's SubjectPublicKeyInfo
           ; credential: what the hub presents as ["link", credential]
Other    = { kind: tstr, params: bstr }   ; params: a CBOR document the hub defines for that kind
```

A document is valid when:

- every node ID follows the node-ID grammar and is not reserved (Hub Profile, section 10.2);
- every node has exactly one link direction: either a `start`, or a `credential` for dialing in, never both and never neither;
- every referenced secret and stored facet exists, every listed facet appears once, and no secret named by a `Dial.credential` is also named by a `NodeConfig.credential`, so a credential the hub presents can never be replayed to it;
- every `Dial.url` is an `https` (WebTransport) or `wss` (WebSocket) URL, and every `pin` is 32 bytes;
- every listed facet is named after its node, and no node with `peer` lists facets;
- every `defaults` key is a 33-byte interface hash and every value a syntactically valid facet name;
- every `Other.kind` and every `extensions` key is one the hub supports, with valid contents.

Defaults are preferences, not checked against live facets: where the named facet is not visible to a session or does not implement the interface, the hub uses its own choice (Hub Profile, section 10.3).

## 4. Watching

`watch` streams the hub's state:

1. The first event is a full `Snapshot`.
2. Then every `RevisionEvent` and `NodeEvent`, in the order they happen. A `NodeEvent` names the revision whose configuration it reflects, so a controller can tell whether a node is up under the configuration it just committed.
3. A hub MAY end a watch that falls too far behind with `Error(resource_exhausted)`; the controller starts a new one, which begins with a snapshot again.

## 5. The interface

The types and methods below make up the interface `sparrow.hub.admin` v1. Test vectors published with the spec give its canonical encoding and interface hash.

### 5.1 Types

| TypeId | Name | Kind | Fields or values (tag: name type) |
| --- | --- | --- | --- |
| 64 | `Config` | struct | 0: nodes `map<string, NodeConfig>`; 1: defaults `optional map<bytes, string>`; 2: extensions `optional map<string, bytes>` |
| 65 | `NodeConfig` | struct | 0: start `optional Start`; 1: credential `optional string`; 2: facets `optional list<bytes>`; 3: peer `optional bool`; 4: enabled `optional bool`; 5: extensions `optional map<string, bytes>` |
| 66 | `Start` | union | 0: spawn `Spawn`; 1: dial `Dial`; 2: other `Other` |
| 67 | `Spawn` | struct | 0: command `list<string>`; 1: env `optional map<string, EnvValue>`; 2: dir `optional string` |
| 68 | `EnvValue` | union | 0: literal `string`; 1: secret `string` |
| 69 | `Dial` | struct | 0: url `string`; 1: pin `bytes`; 2: credential `string` |
| 70 | `Other` | struct | 0: kind `string`; 1: params `bytes` |
| 71 | `Snapshot` | struct | 0: revision `uint`; 1: config `Config`; 2: state `RevisionState`; 3: confirmInMs `optional uint` |
| 72 | `CommitRequest` | struct | 0: base `uint`; 1: config `Config`; 2: confirmWithinMs `uint` |
| 73 | `ValidateRequest` | struct | 0: base `uint`; 1: config `Config` |
| 74 | `Problem` | struct | 0: path `list<string>`; 1: message `string` |
| 75 | `Problems` | alias | `list<Problem>` |
| 76 | `Secret` | struct | 0: name `string`; 1: value `bytes` |
| 77 | `Names` | alias | `list<string>` |
| 78 | `Hashes` | alias | `list<bytes>` |
| 79 | `Event` | union | 0: snapshot `Snapshot`; 1: revision `RevisionEvent`; 2: node `NodeEvent` |
| 80 | `RevisionEvent` | struct | 0: revision `uint`; 1: state `RevisionState`; 2: confirmInMs `optional uint` |
| 81 | `RevisionState` | enum | sigils 64 `pending`, 65 `confirmed`, 66 `rolledBack` |
| 82 | `NodeEvent` | struct | 0: node `string`; 1: revision `uint`; 2: state `NodeState`; 3: message `optional string` |
| 83 | `NodeState` | enum | sigils 67 `starting`, 68 `connected`, 69 `offline`, 70 `failed`, 71 `disabled`, 72 `removed` |

Sigils 64–72 are kind 0 (enum values). `confirmInMs` is the time left before the deadline, measured by the hub when it sent the message, so clocks need not agree. A `Problem.path` lists the keys from the document root to the problem, with list positions as decimal strings, such as `["nodes", "acme.charts", "start"]`.

### 5.2 Methods

One service, 0 `Admin`:

| MethodId | Name | Input | Output | Flags | Behaviour |
| --- | --- | --- | --- | --- | --- |
| 0 | `get` | `unit` | `Snapshot` | idempotent | The applied revision and document, and its state. |
| 1 | `validate` | `ValidateRequest` | `Problems` | idempotent | Validates without changing anything; an empty list means valid. A stale `base` fails with `aborted`. |
| 2 | `commit` | `CommitRequest` | `uint` |  | Validates and applies (sections 2.2, 2.3); returns the new revision. Errors: `aborted` (stale base, or a commit is pending), `failed_precondition` (invalid; `details` is the `dynamic` value `[75, problems]`). |
| 3 | `confirm` | `uint` | `unit` | idempotent | Errors: `not_found`. |
| 4 | `rollback` | `uint` | `uint` |  | Rolls a pending revision back at once and returns the new revision. Errors: `not_found`. |
| 5 | `setSecret` | `Secret` | `unit` |  | Errors: `already_exists`, `invalid_argument` (bad name). |
| 6 | `deleteSecret` | `string` | `unit` | idempotent | Errors: `failed_precondition` (still referenced). |
| 7 | `listSecrets` | `unit` | `Names` | idempotent | Secret names only. |
| 8 | `putFacet` | `bytes` | `bytes` | idempotent | Returns the stored-facet key. Errors: `invalid_argument` (`details` as for `commit`). |
| 9 | `deleteFacet` | `bytes` | `unit` | idempotent | Errors: `failed_precondition` (still referenced). |
| 10 | `listFacets` | `unit` | `Hashes` | idempotent | Stored-facet keys. |
| 11 | `watch` | `unit` | `[3, Event]` | output ends with `End` | Section 4. |

`watch`'s output is a stream, so it sets flag 0x10; no other half is a stream or reaches `[4]`. `watch` does not set the hint flag 0x4, because its first event holds the whole document.
