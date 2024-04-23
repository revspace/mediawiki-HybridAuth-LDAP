<?php

namespace MediaWiki\Extension\HybridAuthLDAP;

use Config;
use HashConfig;
use User;
use MediaWiki\User\UserIdentity;
use MediaWiki\Extension\HybridAuth\HybridAuthSession;

class LDAPHybridAuthSession extends HybridAuthSession {
	/**
	 * @var LDAPHybridAuthProvider
	 */
	protected $ldapProvider;

	/**
	 * @var string
	 */
	protected $ldapDN;

	/**
	 * @var ?string
	 */
	protected $ldapBindDN;

	/**
	 * @var ?string
	 */
	protected $ldapBindPassword;

	public function __construct( LDAPHybridAuthProvider $ldapProvider, string $ldapDN, ?string $ldapBindDN = null, ?string $ldapBindPassword = null) {
		$this->ldapProvider = $ldapProvider;
		$this->ldapDN = $ldapDN;
		$this->ldapBindDN = $ldapBindDN;
		$this->ldapBindPassword = $ldapBindPassword;
	}

	public function getUserID(): ?string {
		return $this->ldapDN;
	}

	public function getUserAttributes( string $attr ): ?array {
		$this->ensureBound();
		$attrs = $this->ldapProvider->getLDAPUser( $this->ldapDN, [ $attr ] );
		return $attrs ? ($attrs[$attr] ?? null) : null;
	}

	public function setUserAttributes( string $attr, ?array $values ): bool {
		$this->ensureBound();
		return $this->ldapProvider->modifyLDAPUser( $this->ldapDN, [ $attr => $values ?? [] ] );
	}

	protected function ensureBound() {
		if ( $this->ldapBindDN && $this->ldapBindPassword) {
			$this->ldapProvider->bindFor( $this->ldapBindDN, $this->ldapBindPassword );
		} else {
			$this->ldapProvider->bindFor( $this->ldapDN );
		}
	}
}
