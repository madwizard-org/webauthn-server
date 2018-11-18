## 1 Introduction

Informative

### 1.1 Use Cases

Informative

#### 1.1.1 Registration

Informative

#### 1.1.2 Authentication

Informative

#### 1.1.3 New device registration

Informative

#### 1.1.4 Other use cases and configurations

Informative

## 2 Conformance

Informative

### 2.1 User Agents

Informative

### 2.2 Authenticators

Informative

#### 2.2.1 Backwards Compatibility with FIDO U2F

Informative, compatibility is fully supported

### 2.3 WebAuthn Relying Parties

See 7

### 2.4 All Conformance Classes

Conforming, but CBOR decoder supports a superset of canonical CBOR and does not strictly reject non-canonical CBOR. 
The CBOR encoder always outputs canonical CBOR though, and maps with duplicate keys are rejected.  

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

#### 5.1.3 Create a new credential - PublicKeyCredential’s \[\[Create\]\](origin, options, sameOriginWithAncestors) method

N/A (client side)

#### 5.1.4 Use an existing credential to make an assertion - PublicKeyCredential’s \[\[Get\]\](options) method

N/A (client side)

##### 5.1.4.1 PublicKeyCredential’s \[\[DiscoverFromExternalSource\]\](origin, options, sameOriginWithAncestors) method

N/A (client side)

#### 5.1.5 Store an existing credential - PublicKeyCredential’s \[\[Store\]\](credential, sameOriginWithAncestors) method

N/A (client side)

#### 5.1.6 Preventing silent access to an existing credential - PublicKeyCredential’s \[\[preventSilentAccess\]\](credential, sameOriginWithAncestors) method

N/A (client side)

#### 5.1.7 Availability of User-Verifying Platform Authenticator - PublicKeyCredential’s isUserVerifyingPlatformAuthenticatorAvailable() method

N/A (client side)

### 5.2 Authenticator Responses (interface AuthenticatorResponse)

Implemented

#### 5.2.1 Information about Public Key Credential (interface AuthenticatorAttestationResponse)

Implemented

#### 5.2.2 Web Authentication Assertion (interface AuthenticatorAssertionResponse)

Implemented

### 5.3 Parameters for Credential Generation (dictionary PublicKeyCredentialParameters)

Implemented

### 5.4 Options for Credential Creation (dictionary PublicKeyCredentialCreationOptions)

Exceptions:

- extensions field is not supported 

#### 5.4.1 Public Key Entity Description (dictionary PublicKeyCredentialEntity)

Implemented

#### 5.4.2 Relying Party Parameters for Credential Generation (dictionary PublicKeyCredentialRpEntity)

Implemented

#### 5.4.3 User Account Parameters for Credential Generation (dictionary PublicKeyCredentialUserEntity)

Implemented

#### 5.4.4 Authenticator Selection Criteria (dictionary AuthenticatorSelectionCriteria)

Implemented

#### 5.4.5 Authenticator Attachment enumeration (enum AuthenticatorAttachment)

Implemented

#### 5.4.6 Attestation Conveyance Preference enumeration (enum AttestationConveyancePreference)

Implemented

### 5.5 Options for Assertion Generation (dictionary PublicKeyCredentialRequestOptions)

Implemented

### 5.6 Abort operations with AbortSignal

N/A (client side)

### 5.7 Authentication Extensions Client Inputs (typedef AuthenticationExtensionsClientInputs)

Not implemented yet

### 5.8 Authentication Extensions Client Outputs (typedef AuthenticationExtensionsClientOutputs)

Not implemented yet

### 5.9 Authentication Extensions Authenticator Inputs (typedef AuthenticationExtensionsAuthenticatorInputs)

Not implemented yet

### 5.10 Supporting Data Structures

Informative

#### 5.10.1 Client data used in WebAuthn signatures (dictionary CollectedClientData)

Implemented internally, exceptions:
- Token binding fields are parsed and validated but actual token binding is not yet supported.  

#### 5.10.2 Credential Type enumeration (enum PublicKeyCredentialType)

Implemented

#### 5.10.3 Credential Descriptor (dictionary PublicKeyCredentialDescriptor)

Implemented

#### 5.10.4 Authenticator Transport enumeration (enum AuthenticatorTransport)

Implemented

#### 5.10.5 Cryptographic Algorithm Identifier (typedef COSEAlgorithmIdentifier)

Implemented

#### 5.10.6 User Verification Requirement enumeration (enum UserVerificationRequirement)

Implemented 

## 6 WebAuthn Authenticator Model
### 6.1 Authenticator data
#### 6.1.1 Signature Counter Considerations
#### 6.1.2 FIDO U2F signature format compatibility
### 6.2 Authenticator taxonomy
#### 6.2.1 Authenticator Attachment Modality
#### 6.2.2 Credential Storage Modality
#### 6.2.3 Authentication Factor Capability
### 6.3 Authenticator operations
#### 6.3.1 Lookup Credential Source by Credential ID algorithm
#### 6.3.2 The authenticatorMakeCredential operation
#### 6.3.3  The authenticatorGetAssertion operation
#### 6.3.4 The authenticatorCancel operation
### 6.4 Attestation
#### 6.4.1 Attested credential data
##### 6.4.1.1 Examples of credentialPublicKey Values encoded in COSE_Key format
#### 6.4.2 Attestation Statement Formats
#### 6.4.3 Attestation Types
#### 6.4.4 Generating an Attestation Object
#### 6.4.5 Signature Formats for Packed Attestation, FIDO U2F Attestation, and Assertion Signatures
## 7 WebAuthn Relying Party Operations
### 7.1 Registering a new credential
### 7.2 Verifying an authentication assertion
## 8 Defined Attestation Statement Formats
### 8.1 Attestation Statement Format Identifiers
### 8.2 Packed Attestation Statement Format
#### 8.2.1 Packed attestation statement certificate requirements
### 8.3 TPM Attestation Statement Format
#### 8.3.1 TPM attestation statement certificate requirements
### 8.4 Android Key Attestation Statement Format
### 8.5 Android SafetyNet Attestation Statement Format
### 8.6 FIDO U2F Attestation Statement Format
### 8.7 None Attestation Statement Format
## 9 WebAuthn Extensions
### 9.1 Extension Identifiers
### 9.2 Defining extensions
### 9.3 Extending request parameters
### 9.4 Client extension processing
### 9.5 Authenticator extension processing
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
## 12 Sample scenarios
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
### 13.4 credentialId Unsigned
### 13.5 Browser Permissions Framework and Extensions
## 14 Privacy Considerations
### 14.1 De-anonymization prevention measures
### 14.2 Anonymous, scoped, non-correlatable public key credentials
### 14.3 Authenticator-local biometric recognition
### 14.4 Attestation Privacy
### 14.5 Registration Ceremony Privacy
### 14.6 Authentication Ceremony Privacy
### 14.7 Privacy between operating system accounts
## 15 Acknowledgements
##  Index
##  Terms defined by this specification
##  Terms defined by reference
##  References
##  Normative References
##  Informative References
##  IDL Index
##  Issues Index
 
