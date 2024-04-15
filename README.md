# HybridAuth-LDAP

MediaWiki extension that implements an LDAP provider for the [HybridAuth](https://github.com/revspace/mediawiki-HybridAuth) extension.

## Configuration

This extension is configured by adding an entry in HybridAuth's `$wgHybridAuthDomains` configuration.
LDAP-specific parameters are then listed in the standard `config` key. For example:

```php
wfLoadExtension( 'HybridAuth' );
wfLoadExtension( 'HybridAuth-LDAP' );

$wgHybridAuthDomains = [
	'revspace.nl' => [
	        /* HybridAuth configuration */
		'provider' => 'HybridAuth-LDAP',
		'user' => [
			'map_type' => 'email',
		],
		/* HybridAuth-LDAP configuration */
		'config' => [
			'connection' => [
				'uri' => 'ldaps://ldap2.space.revspace.nl',
				'base_dn' => 'dc=space,dc=revspace,dc=nl',
			],
			'user' => [
				'base_rdn' => 'ou=people',
				'bind_attr' => 'uid',
				'search_attr' => 'uid',
				'name_attr' => 'uid',
				'realname_attr' => 'cn',
				'settable_attrs' => ['loginShell'],
				'settable_password' => true,
			],
			'group' => [
				'base_rdn' => 'ou=groups',
			],
		],
	],
];
```

Refer to the HybridAuth documentation for standard HybridAuth parameters.
The available HybridAuth-LDAP parameters are:

### `connection`

* `uri`: LDAP server URI to connect to (`proto://host[:port]`);
* `host`: LDAP server host to connect to, if `uri` is not given;
* `port`: LDAP server port to connect to, if `port` is not given;
* `version`: LDAP version to use (default: `3`)
* `referrals`: Whether to enable LDAP referral chasing (default: `true`);
* `tls`: Whether the connection should use TLS. Not to be confused with `starttls` (default: `false`);
* `starttls`: Whether the plaintext connection should be upgraded to TLS by issuing the `STARTTLS` command.
  If no value is given, it is used opportunistically if `tls` is `false`: if the `STARTTLS` command is unsuccessful, it will proceed;
* `tls_ca_file`: CA bundle file for verifying server TLS certificate`;
* `tls_ca_dir`: CA directory for verifying server TLS certificate - filenames should be in [OpenSSL format](https://www.openssl.org/docs/man1.1.1/man3/SSL_CTX_set_default_verify_paths.html);
* `tls_cert_file`: Client certificate file for mutual TLS authentication;
* `tls_cert_key`: Key for client certificate file;

* `base_dn`: Base DN for operations;
* `bind_dn`: Bind DN for privileged operations. Optional, makes changing user attributes without re-entering password possible;
* `bind_rdn`: Bind RDN (relative to base DN) for privileged operations, can be specified instead of `bind_dn`. Optional;
* `bind_pass`: Bind password for privileged operations.

### `user`

* `base_dn`: Base DN for user operations;
* `base_rdn`: Base RDN (relative to general base DN) for user operations, can be specified instead of `base_dn`;

* `bind_attr`: Name of the LDAP attribute that represents the login username in the user DN. Optional, avoids an LDAP server user search if possible;
* `search_attr`: Name of the LDAP attribute that represents the login username in the user entry. Either this or `bind_attr` needs to be specified (default: `uid`);
* `name_attr`: Name of the LDAP attribute that represents the username for user mapping (default: `uid`);
* `email_attr`: Name of the LDAP attribute that represents the email for user mapping (default: `mail`);
* `realname_attr`: Name of the LDAP attribute that represents the realname for user mapping (default `cn`);

* `settable_attrs`: Array of names of LDAP attributes that can be changed through the MediaWiki `Special:ChangeCredentials` UI;
* `settable_password`: Whether the user password can be changed through the MediaWiki `Special:ChangeCredentials` UI;
* `set_needs_auth`: If `connection.bind_dn`is given, set this to `true` if this DN is not privileged enough to change user attributes:
  the user authentication credentials will be asked instead;

### `group`

* `base_dn`: Base DN for group operations;
* `base_rdn`: Base RDN (relative to general base DN) for group operations, can be specified instead of `base_dn`;

## License

GNU General Public License, version 2; see `COPYING` for details.
