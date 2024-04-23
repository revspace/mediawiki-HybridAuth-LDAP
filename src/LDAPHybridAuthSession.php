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

	/**
	 * @var ?string
	 */
	protected $newPassword;

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
		switch ( $attr ) {
		case LDAPHybridAuthProvider::ATTR_NEWPASSWORD:
		case LDAPHybridAuthProvider::ATTR_NEWPASSWORD_CONFIRM:
			return [];
		default:
			$attrs = $this->ldapProvider->getLDAPUser( $this->ldapDN, [ $attr ] );
			return $attrs ? ($attrs[$attr] ?? null) : null;
		}
	}

	public function setUserAttributes( string $attr, ?array $values ): bool {
		$this->ensureBound();
		switch ( $attr ) {
		case LDAPHybridAuthProvider::ATTR_NEWPASSWORD:
			if ( !$values ) {
				return true;
			}
			$this->newPassword = $values[0];
			return true;
		case LDAPHybridAuthProvider::ATTR_NEWPASSWORD_CONFIRM:
			if ( !$values ) {
				return true;
			}
			$password = $this->newPassword;
			$this->newPassword = null;
			if ( $password !== $values[0] ) {
				return false;
			}
			return $this->ldapProvider->modifyLDAPPassword( $this->ldapDN, $password );
		default:
			return $this->ldapProvider->modifyLDAPUser( $this->ldapDN, [ $attr => $values ?? [] ] );
		}
	}

	protected function ensureBound() {
		if ( $this->ldapBindDN && $this->ldapBindPassword) {
			$this->ldapProvider->bindFor( $this->ldapBindDN, $this->ldapBindPassword );
		} else {
			$this->ldapProvider->bindFor( $this->ldapDN );
		}
	}
}
