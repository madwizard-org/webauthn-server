# Conformance to the specification

[Web Authentication API level 1](https://www.w3.org/TR/webauthn/)

## 1 Introduction

Informative

### 1.1 Specification Roadmap

Informative

### 1.2 Use Cases

Informative

#### 1.2.1 Registration

Informative

#### 1.2.2 Authentication

Informative

#### 1.2.3 New Device Registration

Informative

#### 1.2.4 Other Use Cases and Configurations

Informative	

### 1.3 Platform-Specific Implementation Guidance

Informative

## 2 Conformance

Informative

### 2.1 User Agents

Informative

### 2.2 Authenticators

Informative

#### 2.2.1 Backwards Compatibility with FIDO U2F

Informative, backwards compatibility with U2F (via WebAuthn) is fully supported

### 2.3 WebAuthn Relying Parties

Conforming, see 7

### 2.4 All Conformance Classes

CBOR encoder always outputs canonical CBOR.

> All decoders of the above conformance classes SHOULD reject CBOR that is not validly encoded in the CTAP2 canonical CBOR encoding form and SHOULD reject messages with duplicate map keys.
The CBOR decoder is more relaxed and allows non-canonical CBOR, but duplicate map keys are rejected.

## 3 Dependencies

Informative

## 4 Terminology

Informative

## 5 Web Authentication API

Informative

### 5.1 PublicKeyCredential Interface

Exceptions:
- getClientExtensionResults is not supported yet (throws UnsupportedException)

#### 5.1.1 CredentialCreationOptions Dictionary Extension

Supported (unused?)

#### 5.1.2 CredentialRequestOptions Dictionary Extension

Supported (unused?)

#### 5.1.3 Create a New Credential - PublicKeyCredential’s \[\[Create\]\](origin, options, sameOriginWithAncestors) Method

N/A (client side)

#### 5.1.4 Use an Existing Credential to Make an Assertion - PublicKeyCredential’s \[\[Get\]\](options) Method

N/A (client side)

##### 5.1.4.1 PublicKeyCredential’s \[\[DiscoverFromExternalSource\]\](origin, options, sameOriginWithAncestors) Method

N/A (client side)

#### 5.1.5 Store an Existing Credential - PublicKeyCredential’s \[\[Store\]\](credential, sameOriginWithAncestors) Method

N/A (client side)

#### 5.1.6 Preventing Silent Access to an Existing Credential - PublicKeyCredential’s \[\[preventSilentAccess\]\](credential, sameOriginWithAncestors) Method

N/A (client side)

#### 5.1.7 Availability of User-Verifying Platform Authenticator - PublicKeyCredential’s isUserVerifyingPlatformAuthenticatorAvailable() Method

N/A (client side)
### 5.2 Authenticator Responses (interface AuthenticatorResponse)

Implemented

#### 5.2.1 Information About Public Key Credential (interface AuthenticatorAttestationResponse)
Implemented
#### 5.2.2 Web Authentication Assertion (interface AuthenticatorAssertionResponse)

Implemented

### 5.3 Parameters for Credential Generation (dictionary PublicKeyCredentialParameters)

Implemented

### 5.4 Options for Credential Creation (dictionary PublicKeyCredentialCreationOptions)

Exceptions:

- extensions field is not supported yet

#### 5.4.1 Public Key Entity Description (dictionary PublicKeyCredentialEntity)

Implemented

#### 5.4.2 Relying Party Parameters for Credential Generation (dictionary PublicKeyCredentialRpEntity)

Implemented

#### 5.4.3 User Account Parameters for Credential Generation (dictionary PublicKeyCredentialUserEntity)

Implemented, but displayName is not enforced to a specific format in any way

#### 5.4.4 Authenticator Selection Criteria (dictionary AuthenticatorSelectionCriteria)

Implemented

#### 5.4.5 Authenticator Attachment Enumeration (enum AuthenticatorAttachment)

Implemented

#### 5.4.6 Attestation Conveyance Preference Enumeration (enum AttestationConveyancePreference)

Implemented

### 5.5 Options for Assertion Generation (dictionary PublicKeyCredentialRequestOptions)

Exceptions:

- extensions field is not supported yet

### 5.6 Abort Operations with AbortSignal

N/A (client side)

### 5.7 Authentication Extensions Client Inputs (typedef AuthenticationExtensionsClientInputs)

Not implemented yet

### 5.8 Authentication Extensions Client Outputs (typedef AuthenticationExtensionsClientOutputs)

Not implemented yet

### 5.9 Authentication Extensions Authenticator Inputs (typedef AuthenticationExtensionsAuthenticatorInputs)

Not implemented yet

### 5.10 Supporting Data Structures

Informative

#### 5.10.1 Client Data Used in WebAuthn Signatures (dictionary CollectedClientData)

Implemented internally with exceptions:
- Token binding fields are parsed and validated but actual token binding is not yet supported.  

#### 5.10.2 Credential Type Enumeration (enum PublicKeyCredentialType)

Implemented

#### 5.10.3 Credential Descriptor (dictionary PublicKeyCredentialDescriptor)

Implemented

#### 5.10.4 Authenticator Transport Enumeration (enum AuthenticatorTransport)

Implemented

#### 5.10.5 Cryptographic Algorithm Identifier (typedef COSEAlgorithmIdentifier)

Implemented
Work in progress: verify list of supported algorithms

#### 5.10.6 User Verification Requirement Enumeration (enum UserVerificationRequirement)

Implemented

## 6 WebAuthn Authenticator Model

Informative

### 6.1 Authenticator Data

Implemented with exceptions:
- Extension data is parsed but not actually supported yet 

#### 6.1.1 Signature Counter Considerations

Implemented

#### 6.1.2 FIDO U2F Signature Format Compatibility

Informative

### 6.2 Authenticator Taxonomy

Informative

#### 6.2.1 Authenticator Attachment Modality

Informative

#### 6.2.2 Credential Storage Modality

Informative

#### 6.2.3 Authentication Factor Capability

Informative

### 6.3 Authenticator Operations

N/A (client side)

#### 6.3.1 Lookup Credential Source by Credential ID Algorithm

N/A (client side)

#### 6.3.2 The authenticatorMakeCredential Operation

N/A (client side)

#### 6.3.3 The authenticatorGetAssertion Operation

N/A (client side)

#### 6.3.4 The authenticatorCancel Operation

N/A (client side)

### 6.4 Attestation

Informative

#### 6.4.1 Attested Credential Data

Implemented

##### 6.4.1.1 Examples of credentialPublicKey Values Encoded in COSE_Key Format

Informative 

#### 6.4.2 Attestation Statement Formats

Informative

#### 6.4.3 Attestation Types

TODO

#### 6.4.4 Generating an Attestation Object
#### 6.4.5 Signature Formats for Packed Attestation, FIDO U2F Attestation, and Assertion Signatures
## 7 WebAuthn Relying Party Operations
### 7.1 Registering a New Credential
### 7.2 Verifying an Authentication Assertion
## 8 Defined Attestation Statement Formats
### 8.1 Attestation Statement Format Identifiers
### 8.2 Packed Attestation Statement Format
#### 8.2.1 Packed Attestation Statement Certificate Requirements
### 8.3 TPM Attestation Statement Format
#### 8.3.1 TPM Attestation Statement Certificate Requirements
### 8.4 Android Key Attestation Statement Format
#### 8.4.1 Android Key Attestation Statement Certificate Requirements
### 8.5 Android SafetyNet Attestation Statement Format

Supported \
TODO: All verifcation steps from the WebAuthn specifications are implemented, but the [SafetyNet documentation](https://developer.android.com/training/safetynet/attestation#verify-compat-check) mentions additional verification steps (e.g. timestampMs).

### 8.6 FIDO U2F Attestation Statement Format
### 8.7 None Attestation Statement Format
## 9 WebAuthn Extensions
### 9.1 Extension Identifiers
### 9.2 Defining Extensions
### 9.3 Extending Request Parameters
### 9.4 Client Extension Processing
### 9.5 Authenticator Extension Processing
## 10 Defined Extensions
### 10.1 FIDO AppID Extension (appid)
### 10.2 Simple Transaction Authorization Extension (txAuthSimple)
### 10.3 Generic Transaction Authorization Extension (txAuthGeneric)
### 10.4 Authenticator Selection Extension (authnSel)
### 10.5 Supported Extensions Extension (exts)
### 10.6 User Verification Index Extension (uvi)
### 10.7 Location Extension (loc)
### 10.8 User Verification Method Extension (uvm)
### 10.9 Biometric Authenticator Performance Bounds Extension (biometricPerfBounds)
## 11 IANA Considerations
### 11.1 WebAuthn Attestation Statement Format Identifier Registrations
### 11.2 WebAuthn Extension Identifier Registrations
### 11.3 COSE Algorithm Registrations
## 12 Sample Scenarios

Informative

### 12.1 Registration
### 12.2 Registration Specifically with User-Verifying Platform Authenticator
### 12.3 Authentication
### 12.4 Aborting Authentication Operations
### 12.5 Decommissioning
## 13 Security Considerations
### 13.1 Cryptographic Challenges
### 13.2 Attestation Security Considerations
#### 13.2.1 Attestation Certificate Hierarchy
#### 13.2.2 Attestation Certificate and Attestation Certificate CA Compromise
### 13.3 Security Benefits for WebAuthn Relying Parties
#### 13.3.1 Considerations for Self and None Attestation Types and Ignoring Attestation
### 13.4 Credential ID Unsigned
### 13.5 Browser Permissions Framework and Extensions
### 13.6 Credential Loss and Key Mobility
## 14 Privacy Considerations
### 14.1 De-anonymization Prevention Measures
### 14.2 Anonymous, Scoped, Non-correlatable Public Key Credentials
### 14.3 Authenticator-local Biometric Recognition
### 14.4 Attestation Privacy
### 14.5 Registration Ceremony Privacy
### 14.6 Authentication Ceremony Privacy
### 14.7 Privacy Between Operating System Accounts
### 14.8 Privacy of personally identifying information Stored in Authenticators
### 14.9 User Handle Contents
### 14.10 Username Enumeration
## 15 Acknowledgements
##  Index
##  Terms defined by this specification
##  Terms defined by reference
##  References
##  Normative References
##  Informative References
##  IDL Index
##  Issues Index
