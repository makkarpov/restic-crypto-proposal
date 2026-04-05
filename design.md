# restic encryption improvement proposal

*Revision 2.0, author: Maxim Karpov, <me@m-k.mx>*

### Table of contents

* [Introduction](#introduction)
* [Goals](#goals)
  * [Extended threat model](#extended-threat-model)
* [Existing design](#existing-design)
* [Proposed changes](#proposed-changes)
  * [Ciphertext blob identifiers](#ciphertext-blob-identifiers)
  * [Deduplication of c-blobs](#deduplication-of-c-blobs)
  * [Pruning in management mode](#pruning-in-management-mode)
  * [Asymmetric encryption layer](#asymmetric-encryption-layer)
  * [Keyfile changes](#keyfile-changes)
* [Implementation impact](#implementation-impact)
  * [Performance impact](#performance-impact)
  * [Impact on existing repositories](#impact-on-existing-repositories)
  * [Storage backend implementations](#storage-backend-implementations)
  * [Implementation challenges](#implementation-challenges)

## Introduction

This proposal aims to improve restic's cryptographic layer in three broad ways:

* Enable storage backends to enforce correctness constraints, so that malicious actors such as ransomware cannot retroactively corrupt previous backups
* Enable storage backends to perform backup rotation without access to plaintext data
* Enable the use of asymmetric encryption schemes, with a practical focus on gpg as both a key management system and an asymmetric cryptography backend

Personal computers differ from server platforms in an important way: they often contain a large amount of sensitive personal information while also facing a much higher risk of compromise, whether through software vulnerabilities or human error. A server typically runs a relatively fixed set of applications with narrowly defined functions, often reinforced by privilege separation or containerization. A PC, by contrast, routinely executes large amounts of third-party code. Some of this code runs inside virtualized environments, such as browser scripts or file formats that are getting increasingly close to being Turing-complete. Other code is run directly and intentionally: a single *pip install* command can download and execute hundreds of third-party libraries, along with their installation scripts. Unlike servers, which mostly operate unattended, PCs are used interactively by humans, who are fallible even when they are professional software engineers. When a PC is used by someone whose expertise lies outside software, the risk of compromise due to human factors is even higher. At the same time, personal computers often store highly sensitive information that users would not want exposed. In the context of backups, this concern is especially acute, because backups can provide a retrospective view of all data that has existed on the system, even if the original data has long since been deleted.

When considering the ransomware threat specifically, one requirement becomes clear: **the machine being backed up must not be able to delete or corrupt its own backups**, even if it is compromised. This leaves two options. One is to set up a second machine to handle that responsibility. The other is to keep purchasing additional hard drives as storage needs grow. Once privacy requirements are added, the trusted second machine also becomes a scalability bottleneck, because it must hold the repository’s decryption key in order to do its job. For example, if a group of five people wants to back up their personal PCs to a shared server without revealing the contents of their backups, the only practical setup today is for each person to maintain a dedicated Raspberry Pi solely for running pruning jobs.

Finally, under the current cryptographic design, a server cannot reliably enforce append-only semantics. Preventing clients from overwriting files is not sufficient, because outright deletion is not the only way to disrupt a backup system.

This proposal is limited to the cryptographic layer itself. It enables, but does not implement, the supporting infrastructure required for the capabilities described above.

## Goals

This proposal defines a cryptographic mechanism intended to make the following properties achievable for a restic repository:

* **Verifiable append-only safety for past backups**: the cryptographic design should allow a storage backend to validate newly submitted repository objects and reject any submission that would cause the repository to enter an invalid or corrupted state. It should also enable to reject any submission that would corrupt, invalidate, or make previously accepted snapshots or their associated data incorrectly eligible for deletion.
* **Delegable snapshot expiration and data reclamation**: the cryptographic design should allow an entity without plaintext decryption capability to carry out retention-management operations such as *restic forget* and *restic prune*.
* **Forward-only backup capability**: the cryptographic design should support a mode in which a backup producer can create new valid snapshots without holding enough key material to decrypt historical repository contents or data produced by other clients.
* **Separation of backup, management and decryption authority**: the cryptographic design should support distinct cryptographic roles with different capabilities, so that the ability to rotate snapshots, create new snapshots, and decrypt historical data can be granted independently.
* **Enable use of advanced cryptographic tools**: the cryptographic design should support the use of advanced cryptographic tools, such as GPG, along with their surrounding ecosystem, including OpenPGP smartcards and hardware tokens, to protect repository contents.

**Non-goals:**

* Proposed cryptosystem is not intended to replace the current restic symmetric key system. Both systems have their own strengths and their own overhead costs, and expected to coexist simultaneously.

### Extended threat model

With asymmetric encryption mode enabled, basic restic threat model described in the [design document](https://github.com/restic/restic/blob/master/doc/design.rst) is extended. This proposal defines three categories of key material:

* **Management key** grants access to technical repository objects, such as top-level snapshot objects and pack file headers.
* **Backup symmetric key** grants access to repository metadata, including plaintext hashes and the ability to run deduplication queries. **Backup public keys** allow data for new snapshots to be encrypted without granting the ability to decrypt it.
* **Backup private key** grants full access to all stored data. 

Actors who possess none of these keys remain subject to restic’s existing security guarantees and threat model.

Actors with access to the management key:

* **Could** learn high-level data movement patterns, such as the size of each snapshot and how many files were added or deleted.
* **Could** observe chunk reuse patterns across snapshots, files, and different clients, and attempt to infer the nature of such reuse, for example from adjacent reused blobs or data change patterns.
* **Could** group and correlate this knowledge into clusters of closely related directories, projects, or activities, although they would have no direct knowledge of their exact nature, paths, or filenames.
* **Could** view low-level snapshot metadata, such as timestamps, parent snapshots, root backup paths, hostnames and usernames.
* **Could not** decrypt plaintext data or view plaintext hashes.

Actors who also have access to the backup symmetric key:

* **Could** probe previous snapshots to determine whether they contain any of the currently existing files or their chunks, thereby establishing a coarse timeline for when those files or chunks appeared.
* **Could** view plaintext hashes for all blobs in the repository and attempt to guess what data those hashes correspond to.
* **Could** verify such plaintext guesses unambiguously by using the storage deduplication feature.
* **Could** create new snapshots, valid or otherwise, provided the storage backend accepts the snapshot object.
* **Could** mount a DoS attack and degrade performance for other clients using the same repository by creating bogus blobs that the storage backend cannot distinguish from legitimate ones.
* **Could not** retroactively decrypt files from previous snapshots if those files have already been deleted from the host, except through plaintext guessing and deduplication queries.
* **Could not** directly view plaintext filesystem metadata from past snapshots, such as filenames, directory hierarchy, or the exact file-to-blob correspondence, except through plaintext guessing and deduplication queries.
* **Could not** completely prevent other clients from backing up to the same repository, provided the storage backend performs the proposed validations and storage space is not exhausted.
* **Could not** corrupt the repository in a way that would compromise the correctness of other clients' backups.
* Assuming the storage backend implements the proposed validation of incoming objects, **could not** put repository into a state that would cause a legitimate system performing *forget* + *prune* job to erroneously trigger a deletion policy outside of the configured timestamp tolerance window. These policies may still have intricate edge cases, however, so even perfect validation could leave a larger attack surface than anticipated.

Actors who also have access to the backup private key:

* **Could** decrypt all historical data from any existing snapshot.

The threat model presented here relies on the same security assumptions as the standard restic threat model, including the assumption that legitimate hosts create backups correctly using authentic software.

Most of the trade-offs described in this model are a direct consequence of the intended use case. For example, deduplicated backup storage inherently requires a way to determine whether data is identical to data already stored in the repository. Likewise, to delete snapshots, a server must know the exact set of files that belong to a given snapshot, along with the metadata needed to determine whether it should be deleted in the first place.

## Existing design

Before discussing any changes, it never hurts to recap the current system first. A full design document is available in the [restic repository](https://github.com/restic/restic/blob/master/doc/design.rst), but here is a brief summary:

A repository contains a set of **snapshots**, and each snapshot references a set of **blobs**. Each blob is a chunk of data and the atomic unit of deduplication. For storage efficiency, blobs are grouped into larger **packs**, which are then written to the storage server. When files are written to the storage backend, their filenames are derived from the SHA-256 hashes of their contents. This SHA-256 hash is called a **storage ID**.

Blobs cannot exist outside a pack file. A pack file is essentially a concatenated stream of encrypted blobs plus a small encrypted header for efficient indexing. Note that the storage ID is computed over the entire concatenated stream, which severely limits its usefulness for storage backends that want to enforce repository invariants. The only property it can reliably verify is that those specific ciphertexts, in that specific order, hash to the specified value. Any deeper validation would require a decryption key.

A blob can be either a **data blob** or a **tree blob**. Data blobs are binary objects that store the actual chunks of backed-up data. Tree blobs are JSON documents that describe the contents of a single directory, listing the data blobs that must be concatenated to reconstruct a contiguous file, or linking to other tree blobs to represent subdirectories. Snapshots and tree blobs reference other blobs by the SHA-256 hashes of their plaintext contents.

All cryptography is currently symmetric. The repository has a single 256-bit master key, and all data is encrypted with an AEAD algorithm before being written to the storage backend. A set of key files stores the key-derivation parameters needed to derive the master key from repository passwords.

## Proposed changes

Throughout this document, repository operations performed without access to the blob decryption keys are said to operate **in management mode**.

This proposal includes the following cryptographic layer changes:

* **Ciphertext blob identifiers** which allow blob objects to be referenced in a form that can be independently verified by the management system
* **Trusted sets of ciphertext identifiers** and **ciphertext blob validation**, enabling secure deduplication between systems that do not trust one another
* **Blobset blobs**, which allow pruning in management mode without exposing raw tree blobs to the pruning software
* **Asymmetric cryptographic layer** itself to provide the underlying cryptographic primitives
* Changes to the format of keyfiles to accomodate new keying material

The proposal also introduces new information leakage channels to actors possessing the repository management key. Their impact is believed to be very limited and is considered a necessary trade-off to support the intended use cases. Hybrid three-machine setups involving a backup origin machine, a management server, and a "dumb" storage server are still possible when the storage backend is not fully trusted, such as when using a public cloud. In such configurations, the security properties for the storage backend are still expected to hold, since management-key encryption remains effective in all cases.

### Ciphertext blob identifiers

In its current design, restic derives a blob identifier by computing a simple SHA-256 hash of the plaintext blob data. In this document, identifiers derived in this way are referred to as **plaintext identifiers**.

A system operating in management mode must, by definition, trust plaintext blob identifiers blindly: it is not supposed to see the plaintext data and therefore cannot compute the hash independently. However, for pruning to work correctly, the system must be able to unambiguously and securely identify which data must be retained and which data can be safely deleted. Blind trust is not an option here. An adversary could submit a blob containing garbage data while claiming a specific plaintext hash, in the hope of tricking the server into deleting a legitimate blob during pruning. To avoid this, the cryptographic design must provide independently verifiable blob identifiers without revealing the plaintext contents.

The proposed solution is to introduce **ciphertext identifiers** for blobs. Unlike plaintext identifiers, these *can* be independently verified by management software:

```
CiphertextHash := SHA-256(Ciphertext)
MaskedPlaintextData := MaskPlaintextData(SymmetricKey, CiphertextHash, Length(plaintext_blob) || PlaintextID)
CiphertextID := SHA-512/256("CiphertextID\0" || MaskedPlaintextData || CiphertextHash)
```

Ciphertext identifiers are not intended to fully replace or deprecate current plaintext identifiers. Two identifier schemes are expected to coexist. Plaintext identifiers are conceptually simpler and impose less management overhead, so they remain useful for simple symmetric encryption schemes. Implementation is supposed to use ciphertext identifiers only when used encryption scheme explicitly calls for their usage. Blobs using plaintext and ciphertext identification are referred to as **p-blobs** and **c-blobs** respectively.

The final hash uses SHA-512/256 rather than familiar SHA-256 in order to provide domain separation and prevent collisions between two identifier formats. If SHA-256 was to be used as the final hash, it would be trivial to construct a valid p-blob with the same identifier, but completely different data, simply by taking the final hash input and using it directly as blob data.  With SHA-512/256 as the final hash function, it requires finding the SHA-256 preimage instead. Because the final hash function is cryptographically unrelated to the plaintext hash, collisions between the two identifier formats are no more likely than ordinary hash collisions. This allows implementation to continue storing blob identifiers as plain hash strings, without explicitly tagging them as p-blobs or c-blobs. It also means that pruning can safely discard p-blobs that claim the same ID as a c-blob, since such collisions are made negligibly likely by construction.

The plaintext hash and plaintext length are masked to limit metadata leakage to actors who possess only the management key and to prevent such actors from probing plaintext hashes. In the original design, plaintext hashes are stored only in encrypted form under master-key protection. That level of protection is lost when moving to a management-key scheme, so it is reintroduced at the record level.

Making the ciphertext ID depend not only on the ciphertext hash, but also on the claimed plaintext ID and plaintext length, albeit in masked form, effectively binds those header metadata fields against modification. If those fields were not included in the final hash input, a server presented with two blobs that share the same ciphertext but have different header fields would have no way to determine which header is the correct one. Besides being anomalous in itself, such a situation would create cascading complications in the pruning logic: the implementation would have to fall back to the conservative choice of retaining both blobs, and the data structures used to track them would need additional complexity to handle such cases. The ciphertext length is not included in the hash input, since ciphertext hash implicitly binds the ciphertext length as well. For the same reason, the nonce is also omitted from the final hash input: it is stored as part of the ciphertext blob and is therefore already covered by the ciphertext hash.

Note that management software must still trust the claimed masked plaintext data. The goal here, however, is not full plaintext verification, but the ability to unambiguously identify the correct blob in storage. Assuming a legitimate system submitted a c-blob with correct metadata during backup, an attacker cannot trick the management system into discarding it. Validation of externally created c-blobs during backup, where plaintext integrity actually matters, is discussed later.

c-blobs use dedicated entry formats in the pack header. Note that the actual blob ID is not stored explicitly in the header; instead, it is reconstructed from the header fields when the header is parsed.

Type | Meaning | Data
-----|---------|------
0b100 | data blob | `Length(encrypted_blob) \|\| MaskedPlaintextData \|\| Hash(ciphertext) \|\| Nonce`
0b101 | tree blob | `Length(encrypted_blob) \|\| MaskedPlaintextData \|\| Hash(ciphertext) \|\| Nonce`

The `MaskPlaintextData` function, along with its `SymmetricKey` parameter, are defined in the asymmetric encryption section. `Nonce` field is also defined there.

Index files are extended to accommodate the additional metadata required for c-blobs. The presence of the `ciphertext_hash` field indicates that an index entry refers to a c-blob; otherwise, it is assumed to refer to a p-blob. As with pack headers, index entries do not explicitly store c-blob identifiers. Note that `uncompressed_length` field is missing from the c-blob index entires, having been moved into the masked section.

```json
{
  "masked_data": "fa14d4e1af99e26ea99c6d8e0b3cd8474a8a119ed26140fe6cbcfe081087b185d9782612",
  "ciphertext_hash": "1cba0a8cbda7ed5f7a66e753de4062c4974965b5db0b3c127c7a17864936a2c3",
  "nonce": "ff09aa3765cb2aab7564181ef56e8484",
  "type": "data",
  "offset": 38,
  "length": 112
}
```

### Deduplication of c-blobs

With plaintext identifiers, deduplication is relatively straightforward: once a blob with a matching plaintext hash has been found in storage, the system can avoid storing it again and simply reference the existing blob. Because SHA-256 is deterministic, and adaptive chunking aligns the chunk boundaries, identical data naturally maps to the same blobs. This approach does not extend directly to c-blobs. Since a ciphertext identifier depends on the ciphertext hash, deduplication at that level would require a fully deterministic compression and encryption pipeline. Instead, c-blobs are looked up through index files using their plaintext identifiers.

This reintroduces the problem of garbage blobs and the trustworthiness of blob metadata. c-blobs per se do not prevent adversary from submitting garbage blobs claiming bogus hashes in hope of tricking a legitimate system to reference them instead of storing valid data. However, c-blobs bind all metadata fields to the blob ID, thereby making the metadata trustworthy once the c-blob identifier itself has been established as trusted. As a result, a system that maintains a trusted set of c-blob IDs can safely use index files to discover the remaining metadata and then use that metadata to make deduplication decisions based on computed plaintext hashes. If a c-blob is found in the index files but is not yet trusted — for example, when two independent systems store backups in the same repository — trust can be established by downloading the blob and verifying its ciphertext. 

In practice, however, simple deterministic encryption is expected to be a nearly optimal solution for blob verification. Although compression algorithms have no canonical output and may evolve over time, they are not randomized either. The problem of establishing trust in c-blobs arises mainly when one system needs to validate c-blobs produced by another. In such cases, it is reasonable to expect both systems to be running identical or very close restic versions at the time of backup, making it highly likely that the exact ciphertext can be reproduced successfully. And should that fail, downloading and verifying the blob in question would provide a definitive answer.

An adversary with write access and the backup symmetric key could flood the repository with a large number of plausible-looking c-blobs, forcing a legitimate client to download and verify them one by one in an attempt to find a valid match. This type of attack cannot be prevented reliably through backend storage validation, but it could be mitigated to some extent by limiting the number of c-blob verification attempts a client makes before abandoning deduplication and simply writing a new blob. In effect, this would amount to a denial-of-service attack against the storage backend: it would prevent cross-system deduplication (although local deduplication based on a trusted set would still work); it would cause more data to be stored than otherwise necessary; and it would also impose the direct storage cost of the garbage blobs. This does not introduce a new attack vector, since an actor with a repository key and write access could already flood the storage under the current threat model. 

Several methods could be used to store the trusted set of c-blob IDs. The simplest is local storage, with each system maintaining its own set alongside the cached index files. More complex approaches could also be considered, such as adding cryptographic signatures to index files so that a system can trust the contents of index files it created previously. Such approaches may be justified if demand in practical use cases would outweight the additional complexity.

### Pruning in management mode

Pruning a repository requires constructing the set of all reachable blobs and deleting everything else. This traversal begins with snapshots, each of which references a root tree blob, and then proceeds recursively through every referenced tree blob. For pruning to work in management mode, snapshots and tree blobs therefore need to be accessible. The problem is that tree blobs reveal more than just references to data blobs and subtrees: they also leak a substantial amount of filesystem metadata. In personal backups, directory layouts and file names may be nearly as sensitive as the file contents themselves.

To support pruning without disclosing the filesystem structure, this proposal introduces a new blob type: the **blobset**. Each snapshot stores a reference to a root blobset alongside its root tree blob. A blobset contains an arbitrary number of references to data blobs, tree blobs, or other blobsets. The exact shape of the blobset tree is intentionally left loosely defined to preserve implementation flexibility and to allow different trade-offs between complexity, privacy, and efficiency. The only strict requirement is that the root blobset must enumerate, either directly or indirectly, all blobs reachable from the snapshot.

The simplest design would create one blobset per directory, mirroring the corresponding tree blob but with all metadata removed, and link those blobsets together in the same way tree blobs reference one another. At the opposite extreme, a snapshot could contain a single blobset that lists every reachable blob directly. This completely eliminates structural metadata leakage, but it is also the least efficient option in terms of memory usage and deduplication. A hybrid approach could store blobsets only for directories whose paths fall into a lucky hash bucket (`H(path) % N = 0`), while flattening all other directories into their parent blobsets. In that case, `H` would leak a few bits of information about the path name, since the typical value of N is expected to be at most on the order of a few tens. If that becomes a practical concern, a keyed hash function could be used instead.

```javascript
{
  "blobsets": [
    "beba30de3858a1ecc6b19c1f7b47dc384071106657cab6ad8c22ec6858e82419",
    "0f6c674b4738037d341f64b2cbcdcd3fd00c658280da4440829365f2c9934785",
    // ...
  ],
  "trees": [
    "dc10498097a6b735807525cf502d9356d23415e5744fcc906d8f83a4db1fb0ef",
    "f1236bf36c82b38da73f48de88fa4f0d30c7e3cbb507ef941771bb7d41e3554b",
    // ...
  ],
  "data": [
    "bd738a1d167c4734279f9b56b6b4a83295f500760092b379d19f4693698ac5bc",
    "5735ab8b32942122bb772f0af6c3729795cd33362c2a211617497e8935edd5e9",
    "d879267b93e327f10651eb4b5c0a6a95443bd45f80b00afe09fc52dcdd59f3ef",
    // ...
  ]
}
```

Blobsets are optional and may be omitted if the cryptosystem does not provide a dedicated management access mode. In that case, pruning falls back to scanning full tree blobs. Even then, blobsets could still reduce network traffic and improve pruning performance for remote backends, although this proposal does not evaluate whether those benefits justify the additional complexity. To keep the semantics of *prune* precise, however, whenever a snapshot includes a blobset, that blobset — not the raw tree blobs — must be used to determine the reachability set.

Blobsets are always encrypted using the symmetric scheme only, so that systems operating in management mode can read them. For this reason, blobsets are always stored as p-blobs and use only the plaintext pack header entry format:

Type | Meaning | Data
-----|---------|------
0b110 | blobset blob | `Length(encrypted_blob) \|\| Length(plaintext_blob) \|\| Hash(plaintext)`

Because blobsets are readable in management mode, they expose some backup metadata that was previously inaccessible or harder to infer. At a minimum, blobsets reveal the total size of each snapshot and make it possible to infer data movement patterns, such as when files are added or deleted over time, with a precision that depends on the blobset generation granularity. Some of this information may already be inferable by the storage backend through observation of client read and write traffic, while other aspects constitute an entirely new leakage channel or allow more precise inference than before. This is considered a necessary trade-off for supporting pruning in management mode alone.

### Asymmetric encryption layer

The goal of the asymmetric encryption layer, in addition to enabling repository management operations, is to allow the *restic backup* command to run without a private key. This limits a compromised machine to disclosure of only the data currently present, rather than all data that has ever existed on that machine.

The asymmetric encryption layer still retains the existing symmetric master key scheme to protect blobs that are expected to remain readable in management mode: snapshots, indexes, blobsets and pack headers. The asymmetric encryption scheme is used only for data and tree blob contents.

Beyond the usual operations of encrypting with a public key and decrypting with a private key, the asymmetric encryption scheme must support one additional operation: verifying that a given ciphertext is a valid encryption of a given plaintext, without access to the private key needed to decrypt that ciphertext. To support optimistic c-blob verification, the encryption scheme must also be deterministic. This requires a slightly more complex construction than would otherwise be necessary. The proposed cryptographic scheme is as follows:

```
Encrypt(Plaintext, PublicKey, BackupSymmetricKey):
    Nonce := RandomBytes(16)

    PlaintextKey := PlaintextKeyHash(Plaintext)
    EncapKey, SecretKey := EncapsulateKey(PublicKey, PlaintextKey, BackupSymmetricKey, Nonce)
    
    CompressedPlaintext := Compress(Plaintext)
    CiphertextData := AEADEncrypt(Nonce, SecretKey, CompressedPlaintext)
    
    return { Nonce, EncapKey, CiphertextData }
```

Note that this definition is only a logical specification of the data flow and cryptographic operations; it is not intended to serve as a specification for the serialization format or the exact derivation sequence or constants.

The key property that enables ciphertext verification without a private key is that, once the plaintext is known, there is relatively little secret material left to protect. The plaintext itself is used as a secondary decryption key by hashing it again with a different hash function to derive a 256-bit key. The only requirement here is that it must not be possible to reconstruct the plaintext key from the publicly known SHA-256 plaintext hash, so a second hashing pass is unfortunately necessary. Once the plaintext key has been derived, a seed value is used to deterministically derive ephemeral X25519 and ML-KEM keys, along with the corresponding shared secret. These values are then used to encrypt the blob itself.

The remaining cryptographic operations are formally defined as follows:

```
EncryptDeterministic(Nonce, Plaintext, PublicKey, BackupSymmetricKey):
    PlaintextKey := PlaintextKeyHash(Plaintext)
    EncapKey, SecretKey := EncapsulateKey(PublicKey, PlaintextKey, BackupSymmetricKey, Nonce)
    
    CompressedPlaintext := Compress(Plaintext)
    CiphertextData := AEADEncrypt(Nonce, SecretKey, CompressedPlaintext)
    
    return { Nonce, EncapKey, CiphertextData }

Decrypt(Ciphertext, PrivateKey, BackupSymmetricKey):
    { EncapKey, CiphertextData } := Ciphertext
    SecretKey := DecapsulateKey(PrivateKey, EncapKey, BackupSymmetricKey)
    
    CompressedPlaintext := AEADDecrypt(SecretKey, CiphertextData)
    Plaintext := Decompress(CompressedPlaintext)
    
    return Plaintext

Validate(Plaintext, Ciphertext, PublicKey, BackupSymmetricKey):
    { Nonce', EncapKey', CiphertextData' } := Ciphertext
    PlaintextKey := PlaintextKeyHash(Plaintext)
    
    EncapKey, SecretKey := EncapsulateKey(PublicKey, PlaintextKey, BackupSymmetricKey, Nonce')
    if EncapKey' != EncapKey:
        return INVALID
    
    CompressedPlaintext' := AEADDecrypt(SecretKey, CiphertextData')
    Plaintext' := Decompress(CompressedPlaintext')
    if Plaintext' != Plaintext:
        return INVALID
    
    return VALID
```

Actual implementation would also need to store key identifiers for the keys used in the operation, so that key rotation could be implemented: for sake of brevity, formal definitions presented here assume that proper key set has already been pre-selected. 

For the `EncryptDeterministic` function, `AEADEncrypt` is made deterministic by providing an external `Nonce` value from an existing c-blob entry. This function is intended to support fast deduplication checks when index files may already contain a blob with the same plaintext hash. If that check fails, however, there is a risk of encrypting two different plaintexts with the same AEAD nonce. If both ciphertexts were exposed to an external adversary, this would constitute a catastrophic cryptographic failure. For that reason, any ciphertext produced by `EncryptDeterministic` must be discarded immediately if verification fails. The backup process should then continue with ciphertext validation and/or a fresh encryption using a randomly generated nonce.

Because the `Validate` function calls `Decompress` on a potentially untrusted blob, standard countermeasures against zip bombs must be applied. Since a hard length bound already exists in the form of the corresponding plaintext chunk, a robust and simple mitigation is to abort decompression as soon as the output exceeds the plaintext length.

The auxiliary functions are defined as follows:

```
PlaintextKeyHash(Plaintext) := SHA-256("PlaintextKeyHash\0" || Plaintext)

EncapsulateKey(PublicKey, PlaintextKey, SymmetricKey, Nonce):
    { X25519Public, MLKEMPublic } := PublicKey
    
    KeyDerivationKey := KDF(SymmetricKey, Label_BlobKeyDerivationKey, 32)
    StaticSharedKey := KDF(SymmetricKey, Label_BlobStaticSharedKey, 32)
    
    BlobSeedKey := KDF(KeyDerivationKey, PlaintextKey, 32)
    
    X25519EphPrivate := KDF(BlobSeedKey, '\x01' || Nonce, 32)
    X25519EphPublic := X25519Public(X25519EphPrivate)
    X25519Secret := X25519(X25519EphPrivate, X25519Public)
    
    MLKEMSeed := KDF(BlobSeedKey, '\x02' || Nonce, MLKEMSeedLength)
    MLKEMEncap, MLKEMSecret := MLKEMEncapsulate(MLKEMSeed, MLKEMPublic)
    
    EncapKey := { X25519EphPublic, MLKEMEncap }
    SecretKey := SHA-256(X25519Secret || MLKEMSecret || StaticSharedKey)
    
    return { EncapKey, SecretKey }

DecapsulateKey(PrivateKey, EncapKey, SymmetricKey):
    // inverse of EncapsulateKey (X25519 + ML-KEM decapsulation) + static key, omitted for brevity

AEADEncrypt(Nonce, SecretKey, Plaintext):
    // Note: Poly1305AESEncrypt would return Nonce || Ciphertext || MAC as usual
    return Poly1305AESEncrypt(Nonce, SecretKey, Plaintext)

AEADDecrypt(SecretKey, Ciphertext):
    return Poly1305AESDecrypt(SecretKey, Ciphertext)
```

An adversary possessing the symmetric key inherently has the capability to probe repository blobs against known plaintexts, which is a substantial information leak and should be addressed directly rather than dismissed as an unavoidable trade-off. The problem definition — deduplication for a backup performed without a private key, in order to limit retrospective information disclosure — does indeed require *some* form of plaintext probing capability. However, that capability is needed only on the backup origin machine itself, not on the management server. The proposed solution, therefore, is to always maintain two symmetric keys for the repository, one for management tasks and one for the backups.

The same reasoning is applied to the protection of index and pack header entries: plaintext hashes and lengths are not stored there in unencrypted form. Instead, masking is used to prevent actors without the backup symmetric key from learning plaintext hashes or lengths from the metadata:

```
MaskPlaintextData(SymmetricKey, CiphertextHash, Data):
    DataMaskingKey := KDF(SymmetricKey, Label_BlobDataMaskingKey, 32)
    Mask := KDF(DataMaskingKey, CiphertextHash, Length(Data))
    return Data ^ Mask

UnmaskPlaintextData(SymmetricKey, CiphertextHash, Data):
    return MaskPlaintextData(SymmetricKey, CiphertextHash, Data)
```

Again, the actual implementation would need to include key identifiers in the masked data so that the correct decryption key can be selected. Those details are omitted from the definitions here.

### Keyfile changes

The existing restic keyfile mechanism would need to be extended to accommodate the additional key material introduced by this proposal:

* The existing master key would effectively become the management key: the baseline key required to perform any operation on the repository at all. It would be sufficient to perform *forget* and *prune* operations.
* A symmetric backup key would be required to create backups
* Asymmetric public keys would also be required to create backups, even though they do not grant any access on their own.
* Asymmetric private keys would be required to read historical snapshots

Using multiple key files that contain different subsets of these keys would provide a natural and user-friendly way to separate privileges across different actors. Even without exposing users directly to asymmetric cryptography, the system could support three distinct key files, each protected by its own password: one containing only the management key, a second containing the management and backup keys, and a third containing the full key set. This would naturally map to a "management password", a "backup password", and a "master password", which users are likely to find easier to understand than a fully exposed asymmetric-key model. Some of passwords could be combined into a single key file if user does not consider increased complexity to be worth the benefits.

More feature-complete asymmetric encryption tools could also be integrated, with GPG being the most obvious candidate. For example, even the master keyfile could store its private key material only in GPG-encrypted form, making the keyfile alone insufficient to access backup data. Alternatively, the entire key file could simply be a GPG-encrypted blob in a JSON framing, removing the separate password and outer encryption layer entirely and tying access to the corresponding GPG key. Those GPG keys could then be stored on a hardware token, kept offline, or backed up on paper or metal media, benefiting from the broader ecosystem and operational maturity of an established cryptographic toolchain.

## Implementation impact

Preliminary prototyping indicates that differences between the underlying cryptographic systems can largely be abstracted behind a generic Go interface that defines the operations expected from the cryptographic layer. Such an implementation would not only provide transparent support for two cryptosystems simultaneously, but also improve separation of concerns across parts of the codebase that still contain direct, hardcoded calls to raw AES-Poly1305 primitives. Similarly, the keyfile handling logic could be abstracted through a generic interface, allowing the top-level restic code to remain agnostic to the specific cryptographic system in use.

Most of the implementation effort is expected to center on the c-blob support code, since these changes are significantly more invasive and affect large portions of the existing restic codebase. Prototyping suggests that, although the required changes are extensive and varied, implementing c-blob support in a way that imposes almost no overhead on users of the existing cryptographic system while keeping the rest of the restic code generic should be entirely feasible.

The in-memory index structures need to store significantly more data for c-blobs than for p-blobs, and simply extending the index entry structure with additional fields would significantly increase memory consumption for existing users. For this reason, the prototype implementation used separate index trees for p-blobs and c-blobs, with the c-blob tree being allocated lazily when the first c-blob is encountered. This approach kept memory consumption for p-blob-only repositories exactly the same, and the only performance impact on index queries was a single pointer check to determine whether the c-blob index tree pointer is nil. The `Index` structure managed both the p-blob and c-blob index components and presented a unified interface to the rest of the restic code.

The prototyping work was carried out on revision `8a0edde40718630a6f31fd1bdb05c4af3dbb40b7` from September 1, 2024. Although the current codebase has likely diverged enough to make direct code reuse difficult or impossible, and the proposal itself has undergone significant revision since then, the prototype still serves as a useful data point for assessing implementation complexity.

### Performance impact

With regard to backup and restore performance, two major concerns are the cost of the second SHA-256 pass used to derive plaintext keys and the cost of performing an X25519/ML-KEM handshake for each stored blob.

To obtain a rough estimate of the potential performance impact and identify likely bottlenecks, a Go benchmark was run for both X25519-only and X25519/ML-KEM-1024 post-quantum key exchanges, using `cloudflare/circl` library for both X25519 and ML-KEM. The results are shown in the table below. Table cells are formatted as *operations per second (µs per operation)*. All numbers are single-core results.

|                                   | X25519 only     | X25519/ML-KEM-1024 |
|-----------------------------------|-----------------|--------------------|
| Intel Core i9-14900KF             | 32 570 (30.703) | 21 367 (46.800)    |
| AMD Ryzen Threadripper PRO 3955WX | 22 430 (44.582) | 15 687 (63.747)    |

Assuming 1 MB blobs, this corresponds to an upper bound of roughly 15\~21 GB/s of data throughput per core, which far exceeds the single-core performance of any hash or cipher, even with hardware acceleration. For small blobs, it amounts to respectively 15k\~21k blobs per second.

One possible way to address the cost of the second hashing pass would be to replace the SHA-256 plaintext hash with a 512-bit hash and split its output into two halves: the lower 256 bits would serve as the plaintext hash, while the upper 256 bits would be used as the plaintext key for ciphertext verification. One candidate of interest is BLAKE2b, which, although slower than a hardware-accelerated SHA-256 implementation, is still faster than either two-pass SHA-256 or single-pass SHA-512. The benchmarks in the table below use the Go `crypto/sha256`, `crypto/sha512`, and `x/crypto/blake2b` libraries, and measure hashing performance on 1 MB blocks.

|                                   | SHA-256        | SHA-512         | BLAKE2b        |
|-----------------------------------|----------------|-----------------|----------------|
| Intel Core i9-14900KF             | 2 641 (378.55) | 1 030 (970.78)  | 1 491 (670.60) |
| AMD Ryzen Threadripper PRO 3955WX | 1 881 (531.53) |   763 (1 309.3) | 1 087 (919.67) |

Computing the final ciphertext hash for the c-blob introduces yet another hashing pass. This final pass could remain SHA-256, since that function significantly outperforms the alternatives on platforms with hardware acceleration.

Overall, the dominant performance impact is therefore more likely to come from the additional c-blob hashing overhead than from the X25519 or ML-KEM handshakes. The original restic pipeline consisted of a SHA-256 pass over the plaintext data, Poly1305-AES encryption, and a SHA-256 pass for the blob storage ID. The asymmetric-encryption pipeline would instead consist of a BLAKE2b pass over the plaintext data, an X25519/ML-KEM handshake, Poly1305-AES encryption, a SHA-256 pass for the ciphertext hash, and a final SHA-256 pass for the blob storage ID. The changes amount to one additional BLAKE2b pass and one asymmetric handshake, with BLAKE2b dominating for large blobs and the asymmetric handshake dominating for small blobs. The crossover point is likely to be at blob sizes of roughly 50\~100 kB.

|                                   | Poly1305-AES   |
|-----------------------------------|----------------|
| Intel Core i9-14900KF             | 3 478 (287.48) |
| AMD Ryzen Threadripper PRO 3955WX | 2 114 (472.88) |

Using the benchmarked Poly1305-AES result for a 1 MB blob, the estimated pure cryptographic cost is 1.043 ms for the original pipeline and 1.776 ms for the new pipeline. This implies an approximate slowdown of 70%: not ideal, but not prohibitive either. 

Above estimation for both pipelines assumed no data compression, whereas compression time depends heavily on the characteristics of the input. Because this compression cost applies to both pipelines equally, it would further reduce the relative performance gap. Using a tar archive containing all of restic's `*.go` files as an example of a at least somewhat representative dataset (2.5 MB total), the `klauspost/compress/zstd` library was benchmarked at 6.935 ms per operation, or about 2.77 ms per megabyte of source data. Even ignoring the fact that the compressed output is now only about 0.5 MB, this would bring the total to about 3.81 ms for the original pipeline and 4.546 ms for the new one, corresponding to only about 19% slowdown.

### Impact on existing repositories

Existing repositories are expected to continue using the current master-key encryption scheme without any impact on performance or repository size.

Migration of existing repositories to the new cryptographic system is unlikely to be supported, because these repositories contain management objects encrypted with the same master key as the data blobs. Supporting migration would require either downgrading the current master key to a management key, thereby exposing all data and undermining the purpose of the new cryptographic system, or re-encrypting all data blobs under the new scheme, which would be costly. In practice, this would be better handled by creating a new repository and copying the data into it.

To make such transitions easier in the future, the symmetric cryptographic system could be redesigned to use two symmetric keys instead of one: one for encrypting management objects and another for encrypting data or tree blobs. This would preserve the same performance characteristics while allowing a simpler transition, since only the management key would need to be provided to the management server. However, previously stored data in p-blobs could still undermine the purpose of such a transition, as that data would remain vulnerable to malicious overwrites. One possible mitigation would be to introduce an additional validation policy requiring all newly submitted blobs to be c-blobs, preventing new malicious p-blobs from being introduced. The impact of these changes was not analyzed in this proposal, and this paragraph is intended only as food for thought for possible future directions.

### Storage backend implementations

A storage backend that aims to fully benefit from the improved append-only capabilities should implement the following validations:

* Inspect submitted snapshot objects and ensure that their timestamps fall within a reasonable time window. Note that validating the upper bounds (that snapshots don't go into the future) is just as important as validating the lower bounds (that snapshots don't go into the past).

  A more robust alternative would be to issue a timestamped ticket at the start of each backup that binds the critical snapshot parameters, such as the exact timestamp and the parent snapshot ID. This would allow each snapshot to use an exact server-issued timestamp, rather than relying on heuristic time-window checks to reject invalid submissions. That approach is outside the scope of this document, but it could be implemented independently at a later stage.
* Inspect submitted pack files and verify both the validity of their headers and the correctness of the ciphertext hashes recorded in those headers. For ciphertext blobs, this also includes checking that `Nonce` header field matches the actual ciphertext nonce in the blob.
* Inspect submitted index files and verify that all referenced pack files exist and contain the referenced blobs.
* Inspect submitted blobset files and snapshot objects and verify that all referenced blobs exist.
* Validate the storage IDs of submitted files against their actual SHA-256 hashes.
* If retention policies depend on snapshot grouping by metadata fields, check that specific client is authorized to submit a snapshot with claimed metadata.
* If configured and desirable for the specific use case, apply storage usage quotas to the clients so that a single compromised client cannot render the entire storage inoperative with a DoS attack.
* Reject attempts to overwrite or delete existing files.

Depending on the allowed time window, an attacker might still be able to trick forget and prune into deleting *some* of the most recent snapshots, depending on the exact *forget* configuration and the permitted timestamp tolerance. However, deleting *all snapshots in the repository*, as it was previously possible with unvalidated timestamps, should no longer be an attack vector. The earlier attack relied on the ability to submit additional monthly, weekly, or yearly garbage snapshots with timestamps slightly newer than the latest legitimate snapshot, causing those garbage snapshots to become the new retention points. Alternatively, an attacker could submit garbage snapshots with timestamps far in the future, making all legitimate snapshots appear old by comparison. With any reasonable time-window validation, this attack would no longer be possible, because it depends on submitting snapshots whose timestamps are weeks, months, or years in the past or future. Count-based retention policies such as `--keep-last` remain inherently vulnerable to snapshot flooding even under perfect backend validation, and therefore should not be used in environments where this class of attack is a concern.

These constraints are not universally applicable. There are legitimate use cases that require submitting retrospective snapshots, bulk blob uploads without strict referential correctness at each blob, or even outright data deletion. For that reason, a storage backend should use transport-layer authentication to distinguish trusted clients from restricted ones, and apply the above validations only to restricted clients. Privileged credentials could then be stored securely, while routine backup jobs use less-privileged restricted credentials.

### Implementation challenges

* The FIPS 203 standard for ML-KEM post-quantum key exchange strongly discourages implementations from exposing internal deterministic functions except for testing purposes, using a "should not" qualifier.

  Go does expose these functions in the `crypto/mlkem/mlkemtest` package, but it explicitly states that they are intended only for testing and disallows their use in FIPS 140 environments. Cloudflare’s `cloudflare/circl` library is more permissive and directly exposes an `EncapsulateTo` function that accepts a seed argument.

  As a result, both optimistic blob verification and ciphertext verification for ML-KEM depend on a library that is willing to expose these internal functions despite the standard’s recommendation against doing so.

* The ML-KEM algorithm carries a small risk of decapsulation failure, meaning that a receiver with the correct private key may still fail to recover the shared secret. Although the estimated failure probabilities are very low (2<sup>-138</sup> for ML-KEM-512 and 2<sup>-174</sup> for ML-KEM-1024), the issue is qualitative rather than quantitative: it would mean that the backup software includes a cryptographic algorithm that is known to have failure cases.
