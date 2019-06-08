WebAuthn Relying Party server library for PHP
=============================================

[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/madwizard-thomas/webauthn-server/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/madwizard-thomas/webauthn-server/?branch=master)
[![Code Coverage](https://scrutinizer-ci.com/g/madwizard-thomas/webauthn-server/badges/coverage.png?b=master)](https://scrutinizer-ci.com/g/madwizard-thomas/webauthn-server/?branch=master)
[![Build Status](https://scrutinizer-ci.com/g/madwizard-thomas/webauthn-server/badges/build.png?b=master)](https://scrutinizer-ci.com/g/madwizard-thomas/webauthn-server/build-status/master)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Work in progress - use for testing purposes only **

This library aims to implement the relying party server of the WebAuthn specification in PHP. The library is currently being development and not yet ready to be used. APIs may change at any time until the first stable release.

Installation
------------
Installation via composer:
```bash
composer require madwizard/webauthn:^0.0.2
```

Library reference
-----------------
Automatically built reference documentation (for both this library and the separate Symfony bundle): \
https://madwizard-thomas.github.io/webauthn/

Symfony bundle
--------------

If you want to integrate this library in a symfony project, have a look at the [webuathn-server-bundle](https://github.com/madwizard-thomas/webauthn-server-bundle) package.

Support
-------

This library is still in development! Currently supported features are:

Attestation types:
- FIDO U2F
- Packed
- TPM
- Android SafetyNet
- Android Key 
- None

Attestation is not yet verified with trusted anchors (I'm working on this) or the metadata service but the attestation itself is validated for correctness and consistency.

Usage
-----

The library is still in development so documentation is limited. The general pattern to follow is:

1. Write a class implementing `UserCredentialInterface`.
2. Implement `CredentialStoreInterface`.
3. Create an instance of `WebAuthnServer` with a `WebAuthnConfiguration` object and the credential store.
4. Use `startRegistration`/`finishRegistration` to register credentials. Be sure to store the temporary `AttestationContext` server side! 
5. and `startAuthentication`/`finishAuthentication` to authenticate. . Be sure to store the temporary `AssertionContext` server side! 
    
Resources
---------
[WebAuthn specification](https://www.w3.org/TR/webauthn/)
