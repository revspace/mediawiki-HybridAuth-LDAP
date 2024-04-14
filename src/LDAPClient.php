<?php

namespace MediaWiki\Extension\HybridAuthLDAP;

class LDAPClient {
	const CONFIG_URI       = 'uri';
	const CONFIG_PROTO     = 'proto';
	const CONFIG_HOST      = 'host';
	const CONFIG_VERSION   = 'version';
	const CONFIG_REFERRALS = 'referrals';
	const CONFIG_TLS       = 'tls';
	const CONFIG_STARTTLS  = 'starttls';
	const CONFIG_CA_BUNDLE = 'tls_ca_file';
	const CONFIG_CA_DIR    = 'tls_ca_dir';
	const CONFIG_CERT      = 'tls_cert_file';
	const CONFIG_CERTKEY   = 'tls_certkey_key';
	const CONFIG_PORT      = 'port';
	const CONFIG_BASE_DN   = 'base_dn';
	const CONFIG_BIND_DN   = 'bind_dn';
	const CONFIG_BIND_RDN  = 'bind_rdn';
	const CONFIG_BIND_PW   = 'bind_pass';

	/**
	 * @var array
	 */
	protected $domainConfig;

	/**
	 * @var resource
	 */
	protected $conn;

	/**
	 * @var bool|string Whether the client is bound at the moment or not
	 */
	protected $boundAs;


	public function __construct( $config ) {
		$this->config = $config;
		$this->boundAs = false;
		$this->connect();
	}

	public function getConfig( string $key, $default = null ) {
		return $this->config->has( $key ) ? $this->config->get( $key ) : $default;
	}

	public function getBaseDN(): string {
		return $this->getConfig( static::CONFIG_BASE_DN );
	}

	/**
	 * Returns a string which has the chars *, (, ), \ & NUL escaped
	 * to LDAP compliant syntax as per RFC 2254 Thanks and credit to
	 * Iain Colledge for the research and function.
	 *
	 * Taken from original "Extension:LdapAuthentication" by Ryan Lane
	 *
	 * @param string $value working with this
	 */
	public static function escape( string $value ): string {
		// Make the string LDAP compliant by escaping *, (, ) , \ & NUL
		return str_replace(
			[ "\\", "(", ")", "*", "\x00" ],
			[ "\\5c", "\\28", "\\29", "\\2a", "\\00" ],
			$value
		);
	}

	protected function connect(): void {
		$uri = $this->getConfig(static::CONFIG_URI);
		$host = $this->getConfig( static::CONFIG_HOST );
		if ( !$uri ) {
			$tls = $this->getConfig( static::CONFIG_TLS, false );
			$proto = $this->getConfig( static::CONFIG_PROTO, ($tls ? 'ldaps' : 'ldap') );
			$port = $this->getConfig( static::CONFIG_PORT );
			if ( $port ) {
				$host .= ":" . str( $port );
			}
			$uri = "{$proto}://{$host}";
		}
		$this->conn = \ldap_connect( $uri );
		if ( $host ) {
			\ldap_set_option( $this->conn, LDAP_OPT_HOST_NAME, $host );
		}
		\ldap_set_option( $this->conn, LDAP_OPT_PROTOCOL_VERSION,
			$this->getConfig( static::CONFIG_VERSION, 3 ) );
		\ldap_set_option( $this->conn, LDAP_OPT_REFERRALS,
			$this->getConfig( static::CONFIG_REFERRALS, true ) );
		$caBundle = $this->getConfig( static::CONFIG_CA_BUNDLE );
		if ( $caBundle && defined( 'LDAP_OPT_X_TLS_CACERTFILE' ) ) {
			\ldap_set_option( $this->conn, LDAP_OPT_X_TLS_CACERTFILE, $caBundle );
		}
		$caDir = $this->getConfig( static::CONFIG_CA_DIR );
		if ( $caDir && defined( 'LDAP_OPT_X_TLS_CACERTDIR' ) ) {
			\ldap_set_option( $this->conn, LDAP_OPT_X_TLS_CACERTDIR, $caDir );
		}
		$clientCert = $this->getConfig( static::CONFIG_CERT );
		if ( $clientCert && defined( 'LDAP_OPT_X_TLS_CERTFILE' ) ) {
			\ldap_set_option( $this->conn, LDAP_OPT_X_TLS_CERTFILE, $clientCert );
		}
		$clientKey = $this->getConfig( static::CONFIG_CERTKEY );
		if ( $clientKey && defined( 'LDAP_OPT_X_TLS_KEYFILE' ) ) {
			\ldap_set_option( $this->conn, LDAP_OPT_X_TLS_KEYFILE, $clientKey );
		}
		if ( $this->getConfig(static::CONFIG_STARTTLS, false) ) {
			\ldap_start_tls( $this->conn );
		}
	}

	public function bind(): bool {
		$bindDN = $this->getConfig( static::CONFIG_BIND_DN );
		if ( !$bindDN ) {
			$bindRDN = $this->getConfig( static::CONFIG_BIND_RDN );
			if ( $bindRDN ) {
				$bindDN = $bindRDN . "," . $this->getBaseDN();
			}
		}
		$bindPW = $this->getConfig( static::CONFIG_BIND_PW );
		if ( $bindDN && $bindPW ) {
			$bound = $this->bindAs ( $bindDN, $bindPW );
		} else {
			$bound = $this->bindAnon( $bindDN );
		}
		if ( $bound ) {
			$this->boundAs = true;
		}
		return $bound;
	}

	public function bindAnon( ?string $dn = null ) {
		$bound = \ldap_bind( $this->conn, $dn, null );
		/* only update if successful, as we can retain old binding */
		if ( $bound ) {
			$this->boundAs = true;
		}
		return $bound;
	}

	public function bindAs( string $dn, string $password ) {
		$bound = \ldap_bind( $this->conn, $dn, $password );
		/* only update if successful, we can retain old binding */
		if ( $bound ) {
			$this->boundAs = $dn;
		}
		return $bound;
	}

	public function unbind() {
		if ( \ldap_unbind( $this->conn ) ) {
			$this->boundAs = false;
		}
	}

	public function isBound(): bool {
		return $this->boundAs;
	}

	public function isBoundFor( string $dn ): bool {
		return $this->boundAs === true || $this->boundAs === $dn;
	}


	protected function ensureBound(): void {
		if ( $this->isBound() )
			return;
		if ( !$this->bind() ) {
			throw new LDAPException( $this, "Could not bind to server" );
		}
	}

	public function read( string $dn, ?array $attributes = null, ?array $filters = null): ?array {
		$this->ensureBound();

		$filterString = static::formatFilterString( $filters );
		$r = \ldap_read( $this->conn, $dn, $filterString, $attributes ?? [] );
		if ( !$r ) {
			return null;
		}
		$entries = $this->getEntries( $r, $attributes );
		return $entries ? $entries[0] : null;
	}

	public function modify( string $dn, array $attributes ): bool {
		$this->ensureBound();
		return \ldap_mod_replace( $this->conn, $dn, $attributes );
	}

	public function search( array $attributes, ?array $filters = null, ?string $dn = null ): ?array {
		$this->ensureBound();

		$filterString = static::formatFilterString( $filters );
		if ( !$dn ) {
			$dn = $this->getConfig( static::CONFIG_BASE_DN );
		}
		$r = \ldap_search( $this->conn, $dn, $filterString, $attributes ?? [] );
		if ( !$r ) {
			return null;
		}
		return $this->getEntries( $r, $attributes );
	}

	public function parseDN( string $dn ): ?array {
		$parts = \ldap_explode_dn( $dn, 0 );
		if ( $parts === false ) {
			return null;
		}
		$attrs = [];
		foreach ( static::normalizeArr( $parts ) as $part ) {
			if ( strstr( $part, '=' ) === false ) {
				return null;
			}
			[$attr, $value] = explode( '=', $part );
			if ( !isset( $attrs[$attr] ) ) {
				$attrs[$attr] = [];
			}
			$attrs[$attr][] = $value;
		}
		return $attrs;
	}

	protected function getEntries( $res, ?array $attributes ): array {
		$entries = [];
		$entry = \ldap_first_entry( $this->conn, $res );
		while ( $entry ) {
			$values = \ldap_get_attributes( $this->conn, $entry );
			$e = static::normalizeMap( $values );
			if ( $attributes ) {
				if ( !isset( $e["dn"] ) && in_array( "dn", $attributes ) ) {
					$e["dn"] = \ldap_get_dn( $this->conn, $entry );
				}
			} else {
				$dn = \ldap_get_dn( $this->conn, $entry );
				if ( $dn !== false ) {
					$e["dn"] = $dn;
				}
			}
			$entries[] = $e;
			$entry = \ldap_next_entry( $this->conn, $entry );
		}
		return $entries;
	}

	protected static function formatFilterString( ?array $filters ) {
		if ( !$filters ) {
			return '(objectClass=*)';
		}

		$filterParts = [];
		foreach ( $filters as $key => $value ) {
			if ( is_int( $key ) ) {
				$filterParts[] = "({$value})";
			} else {
				if ( $value ) {
					$escapedValue = static::escape( $value );
					$filterParts[] = "({$key}={$escapedValue})";
				} else {
					$filterParts[] = "(!({$key}=*))";
				}
			}
		}
		if ( count($filterParts) === 1 ) {
			return $filterParts[0];
		}
		return "(&" . implode( $filterParts ) . ")";
	}

	protected static function normalizeMap( $value ) {
		if ( is_array( $value ) && isset( $value["count"] ) ) {
			$normalized = [];
			for ( $i = 0; $i < $value["count"]; $i++ ) {
				$key = $value[$i];
				$normalized[$key] = static::normalizeArr( $value[$key] );
			}
			return $normalized;
		}
		return $value;
	}

	protected static function normalizeArr( $value ) {
		if ( is_array( $value ) && isset( $value["count"] ) ) {
			$normalized = [];
			for ( $i = 0; $i < $value["count"]; $i++ ) {
				$normalized[] = static::normalizeArr( $value[$i] );
			}
			return $normalized;
		}
		return $value;
	}
}
