This sample SP has been retired. It was used for early prototyping for integrations with login.gov and has not been maintained. It has confirmed vulnerabilities and should not be used for production itegrations.

For maintained examples of integrations with login.gov please refer to:

- https://github.com/18F/identity-saml-sinatra
- https://github.com/18F/identity-oidc-sinatra

# OpenID Connect Client for Spring Boot

This example application demonstrates how to configure an OpenID Connect client for Spring Boot to connect to the [login.gov](https://login.gov/) identity service. 

## Quick Start

If you'd like to just get started, this app should work right out of the box and connect to the integration and testing environment. See the service documentation for test account user credentials. Due to security restrictions on the identity server, the demo application will only work when accessed from `https://localhost:8080/` unless it is reconfigured. 

To connect to a different service, you will need to register your client with that service. After regitration, edit the `application.properties` file and fill in the appropriate values for that service. You'll also need to generate a new key pair and place it, in JWKS format, in `src/main/resources/keystore.jwks`, making sure to register this key. See the utility site [mkjwk](https://mkjwk.org/) for more information on key generation.

## More Details

Login.gov uses the same OpenID Connect standard that other providers like Google use, but using a high security profile. This profile requires things like strict redirect URI matching and key-based client authentication. You can use any standards-compliant library that supports these high security options to connect to login.gov. 

This sample project uses the client library of the [MITREid Connect](https://github.com/mitreid-connect/) project for all of its security processing. The MITREid Connect project is very flexible and has in-depth documentation available for further reference. This sample project configures this library to use the most common options required by login.gov. 

The MITREid Connect library is built on top of Spring Security which needs to be configured as well. If your project is not yet configured with Spring Security, please see the Spring Security documentation for instructions on how to do so.

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

## Accessing the Logged-in User

A successful login will create an `OIDCAuthenticationToken` object and place it into the security context of your application. This can be injected as the `Authentication` object within your application's classes. This can be used to uniquely identify the current user and access profile information about that user.

### User Uniqueness

Users in OpenID Connect are uniquely identified by a pair of attributes: the _issuer_ and _subject_. The _issuer_ uniquely identifies the identity provider, while the _subject_ uniquely identifies the user within that identity provider's domain. When a user logs in to an application from the same identity provider multiple times, the identity provider will send the same subject value each time. 

It's important to note that the subject alone cannot uniquely identify a user in the world. Two different identity providers could re-use the same subject to refer to different users, and the same user could have different subjects from different identity providers. Therefore, it is imperitive to use these two components together to uniquely identify the user. The MITREid Connect library automatically creates a security `Principal` object based on these two fields that is accessible from the `Authentication` object. Additionally, the `OIDCAuthenticationToken` class allows direct access to both the `iss` and `sub` fields.

Other fields, such as `email` and `preferred_username`, could be the same for multiple users within a given identity provider, and there is no guarantee of validity or uniqeness of these values across identity providers. Therefore, these and other user profile information fields should never be used to identify the user. 

### Profile Information

Most applications don't want to just know that somebody unique logged in, they want to know information about who has done so. In OpenID Connect, this information is called _user info_ and is automatically fetched by the client from the identity provider's _user info endpoint_. These fields are made available from the `OIDCAuthenticationToken.getUserInfo()` function. The fields are not guaranteed to be filled in, and what's available is based on what your application requested, what the user consented to, and ultimately what the identity provider returned. 

### Roles

By default, the MITREid Connect client library assigns a Spring Security role of `ROLE_USER` to all valid logged-in users. This can be used to control access to functions within your application. For example, any pages that would require a login can be annotated with `hasRole('ROLE_USER')`, and Spring Security will automatically start the login process if the user is not currently logged in. 

To add additional roles, you need to configure a custom `OIDCAuthoritiesMapper` class. This takes in information about the user from both the ID Token as well as the user's profile information from the user info endpoit. The client library has a simple implementation of this class called `NamedAdminAuthoritiesMapper` which takes in a list of subject/issuer pairs that will be assigned the role of `ROLE_ADMIN` in addition to the default `ROLE_USER`. This is useful for creating applications that have privileged users, but configuration of this has been left out of the demonstration application.

Additonally, the client library adds a Spring Security `GrantedAuthority` based on the subject and issuer of the current logged in user. This takes the form of `OIDC_subject_issuer` and can be accessed along with the rest of the authorities assigned to the current authentication object representing the user. 
