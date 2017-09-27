# OpenID Connect Client for Spring Boot

This example application demonstrates how to configure an OpenID Connect client for Spring Boot to connect to the [login.gov](https://login.gov/) identity service. 

## Quick Start

If you'd like to just get started, this app should work right out of the box and connect to the integration and testing environment. See the service documentation for test account user credentials. Due to security restrictions on the identity server, the demo application will only work when accessed from `https://localhost:8080/` unless it is reconfigured. 

To connect to a different service, you will need to register your client with that service. After regitration, edit the `application.properties` file and fill in the appropriate values for that service. You'll also need to generate a new key pair and place it, in JWKS format, in `src/main/resources/keystore.jwks`, making sure to register this key. See the utility site [mkjwk](https://mkjwk.org/) for more information on key generation.

## More Details

Login.gov uses the same OpenID Connect standard that other providers like Google use, but using a high security profile. This profile requires things like strict redirect URI matching and key-based client authentication.

This sample project uses the client library of the [MITREid Connect](https://github.com/mitreid-connect/) project for all of its security processing. This library is built on top of Spring Security. If your project is not yet configured with Spring Security, please see the Spring Security documentation for instructions on how to do so.

### Web Security Configuration

The security of this project is handled through Spring Boot annotations, and in particular the `WebSecurityConfig` class found in the `src/main/java/hello/WebSecurityConfig.java` file of this project. Most importantly, this class configures the `OIDCAuthenticationFilter`, which handles the heavy lifting of the OpenID Connect protocol. The filter listens on a special URL path of `/openid_connect_login` within your application's context, and this forms the basis of your application's _redirect URI_, sometimes known as the _callback URL_. This is the URL that the identity server uses to communicate back to your application during the OpenID Connect process, and it needs to be served in a way that's reachable by the end user who's logging in. 

The filter makes use of several helper utilities to do its work, all of which are also configured in the same file. These include:

 * `JWKSetCacheService`: fetches the server's public keys from remote URLs 
 * `JWKSetKeyStore`: loads your application's public and private keys from a file (see configuration section below)
 * `JWTSigningAndValidationService`: uses your application's public and private keys to sign outgoing requests and validate signatures from the identity server

Additionally, many attributes used by these components are configurable through properties. You can customize the filter configuration by either editing the `application.properties` file or by editing the `WebSecurityConfig` class itself. 

### Filter Configuration

The filter is configured with five key components:

 * `IssuerService`: tells your application which identity provider to talk to; this is set statically to a single server
 * `ServerConfigurationService`: gives your application details about that identity provider; this information is discovered automatically from the `issuer`
 * `ClientConfigurationService`: gives your application details about itself needed to talk to the identity provider; this information is configured statically within the class or properties
 * `AuthRequestOptionsService`: allows your application to send special request options; this is configured to be a pass through
 * `AuthRequestUrlBuilder`: tells your application how to redirect the user to the identity provider to start the login process; this demo application uses a simple URL

Of all of these components, the only ones that will generally vary per configuration are the `IssuerService` and the `ClientConfigurationService`. You'll also need to generate and configure a public and private keypair for your client. These items are covered in the sections below.

### Issuer Service

The underlying MITREid Connect client library is general purpose and not tied to any specific provider. To make sure your application speaks only to login.gov, you need to configure the `issuer` to be a single, static value. This will cause the application to reject any attempts to log in with a different identity provider.

The `issuer` is always a URL, and unless you're in a testing environment with no real user data, this URL needs to start with `https` for security. The `issuer` serves as a unique identifier for the identity provider server, and it is used by the client application to discover information about the server such as which URL to redirect the user to (the _authorization endpoint_), which URL to fetch user profile information from (the _user info endpoint_), how to get the server's public key, among others. Additionally, when your application is issued an ID Token during the login process, that ID Token will have an `iss` field that will contain the `issuer` URL from the identity provider. Any ID Tokens that don't contain this field and value will be rejected by the client library.

### Client Configuration Service

The login.gov service requires static registration of your client application with the identity provider (see the login.gov documentation for details). In this process, you'll upload your public key to the identity provider and be issued a _client identifier_ (also known as a _client id_). You'll need to configure the client id in your application to match the one registered at the server. 

Your application will also have a _redirect URI_, sometimes called a _callback URL_. This URL is used in the OpenID Connect protocol for the identity provider to send information back to your application as part of the login process. Unless you are in a testing environment, this URL needs to be secure in one of the following ways:

  * protected by HTTPS
  * served from the user's machine (on `localhost` or similar)
  * accessed via a non-HTTP applicaiton-specific URI (such as `myapp:/` on a mobile device)
  
The redirect URI is handled by the security filter, and it will live on `/openid_connect_login`. For example, if your application is served from `https://example.com/awesome` then your redirect URI will be `https://example.com/awesome/openid_connect_login` when using this library. The library does not automatically detect or calculate this URI, and therefore it must be configured explicitly. 

### Cryptographic Key Configuration

The MITREid Connect client library requires your application's public and private key pair to be in the JSON Web Key Set (JWKS) format. By default, this is contained in the file `src/main/resources/keystore.jwks`. The path to this file can be changed with the `keystorepath` property. Within this file, there needs to be at least one RSA keypair that has been registered with the identity provider. The registered key is identified by the `kid` (or _key id_) field in the key itself, which needs to match the `defaultkey` property in the filter configuration. The default value used with the demo application is `rsa-test-key`, and this should be changed to reflect the `kid` field of the key. 

Due to the design of the protocol, the keys used for OpenID Connect do not need to come from a certificate authority or other third party. As such, it is recommended that you securely generate your keys directly. There are several utilities for doing this, and more information can be found at the [mkjwk](https://mkjwk.org/) website provided by MIT.