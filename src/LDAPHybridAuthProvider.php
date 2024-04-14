<?php

namespace MediaWiki\Extension\HybridAuthLDAP;

use Config;
use HashConfig;
use Message;
use User;
use MediaWiki\User\UserIdentity;
use MediaWiki\Extension\HybridAuth\HybridAuthProvider;
use MediaWiki\Extension\HybridAuth\HybridAuthSession;

class LDAPHybridAuthProvider extends HybridAuthProvider {
	const CONFIG_CONNECTION = 'connection';
	const CONFIG_USER = 'user';
	const CONFIG_GROUP = 'group';

	const USERCONFIG_BASE_DN       = 'base_dn';
	const USERCONFIG_BASE_RDN      = 'base_rdn';
	const USERCONFIG_NAME_ATTR     = 'name_attr';
	const USERCONFIG_REALNAME_ATTR = 'realname_attr';
	const USERCONFIG_EMAIL_ATTR    = 'email_attr';
	const USERCONFIG_SEARCH_FILTER = 'search_filter';
	const USERCONFIG_SEARCH_ATTR   = 'search_attr';
	const USERCONFIG_BIND_ATTR     = 'bind_attr';
	const USERCONFIG_SETTABLE_ATTRS = 'settable_attrs';
	const USERCONFIG_SETTABLE_PASSWORD = 'settable_password';
	const USERCONFIG_SET_NEEDS_AUTH = 'set_needs_auth';

	/**
	 * @var string
	 */
	protected $domain;

	/**
	 * @var Config
	 */
	protected $config;

	/**
	 * @var LDAPClient
	 */
	protected $ldapClient;

	/**
	 * @var Config
	 */
	protected $userConfig;

	/**
	 * @var Config
	 */
	protected $groupConfig;

	public function __construct( string $domain, Config $config ) {
		$this->domain = $domain;
		$this->config = $config;

		$connConfig = new HashConfig( $this->getConfig( static::CONFIG_CONNECTION, [] ) );
		$this->ldapClient = new LDAPClient( $connConfig );
		$this->userConfig = new HashConfig( $this->getConfig( static::CONFIG_USER, [] ) );
		$this->groupConfig = new HashConfig( $this->getConfig( static::CONFIG_GROUP, [] ) );
	}

	public function getConfig( string $key, $default = null ) {
		return $this->config->has( $key ) ? $this->config->get( $key ) : $default;
	}

	public function getUserConfig( string $key, $default = null ) {
		return $this->userConfig->has( $key ) ? $this->userConfig->get( $key ) : $default;
	}

	public function getGroupConfig( string $key, $default = null ) {
		return $this->groupConfig->has( $key ) ? $this->groupConfig->get( $key ) : $default;
	}

	/* HybridAuthProvider API */
	public function getDescription(): string {
		return wfMessage( 'ext.hybridauth.ldap.provider-desc' )->text();
	}

	public function getAuthenticationFields( ?string $providerUserID = null ): array {
		if ( $providerUserID !== null ) {
			$username = $this->reverseLookupLDAPUser( $providerUserID );
		} else {
			$username = null;
		}
		$fields = [
			'username' => [
				'type' => $username ? 'hidden' : 'string',
				'label' => wfMessage( 'userlogin-yourname' ),
				'help' => wfMessage( 'authmanager-username-help' ),
			],
			'password' => [
				'type' => 'password',
				'label' => wfMessage( 'userlogin-yourpassword' ),
				'help' => wfMessage( 'authmanager-password-help' ),
				'sensitive' => true,
			],
		];
		if ( $username !== null ) {
			$fields['username']['value'] = $username;
		}
		return $fields;
	}

	public function getAttributeFields( string $providerUserID ): array {
		$fields = [];
		if ( $this->getUserConfig( static::USERCONFIG_SETTABLE_PASSWORD, false ) ) {
			$fields = array_merge( $fields, [
				'new_password' => [
					'type' => 'password',
					'label' => wfMessage( 'newpassword' ),
					'help' => wfMessage( 'authmanager-password-help' ),
					'sensitive' => true,
					'optional' => true,
				],
				'new_retype' => [
					'type' => 'password',
					'label' => wfMessage( 'retypenew' ),
					'help' => wfMessage( 'authmanager-retype-help' ),
					'sensitive' => true,
					'optional' => true,
				],
			] );
		}
		$ldapAttrs = $this->getUserConfig( static::USERCONFIG_SETTABLE_ATTRS, [] );
		foreach ( $ldapAttrs as $ldapAttr ) {
			$attrLabel = wfMessage( "ext.hybridauth.ldap.attr.{$ldapAttr}-label" );
			if ( !$attrLabel->exists() ) {
				$attrLabel = wfMessage( "ext.hybridauth.ldap.attr-label", [ $ldapAttr ] );
			}
			$fields[$ldapAttr] = [
				'type' => 'string',
				'label' => $attrLabel,
				'help' => $attrLabel,
				'optional' => true,
			];
		}
		return $fields;
	}

	public function authenticate( array $values, ?Message &$errorMessage ): ?HybridAuthSession {
		$errorMessage = null;
		$username = $values['username'] ?? null;
		$password = $values['password'] ?? null;
		if ( !$username || !$password ) {
			return null;
		}

		$dn = $this->lookupLDAPUser( $username, $errorMessage );
		if ( !$dn ) {
			return null;
		}
		if ( !$this->ldapClient->bindAs( $dn, $password ) ) {
			return null;
		}
		return new LDAPHybridAuthSession( $this, $dn, $dn, $password );
	}

	public function canSudo( string $providerUserID ): bool {
		if ( $this->getUserConfig( static::USERCONFIG_SET_NEEDS_AUTH, false ) ) {
			return false;
		}
		return $this->bindFor( $providerUserID );
	}

	public function sudo( string $providerUserID, ?Message &$errorMessage ): ?HybridAuthSession {
		if ( !$this->bindFor( $providerUserID) ) {
			return null;
		}
		return new LDAPHybridAuthSession( $this, $providerUserID );
	}

	public function mapUserAttribute( string $attr ): ?string {
		switch ( $attr ) {
		case static::USERATTR_NAME:
			return $this->getUserConfig( static::USERCONFIG_NAME_ATTR, 'uid' );
		case static::USERATTR_EMAIL:
			return $this->getUserConfig( static::USERCONFIG_EMAIL_ATTR, 'mail' );
		case static::USERATTR_REALNAME:
			return $this->getUserConfig( static::USERCONFIG_REALNAME_ATTR, 'cn' );
		default:
			return null;
		}
	}


	/* LDAP shenanigans */
	/**
	 * Bind for user
	 */
	public function bindFor( string $dn, ?string $password = null ): bool {
		if ( $this->ldapClient->isBoundFor( $dn ) ) {
			return true;
		}
		return $password ? $this->ldapClient->bindAs( $dn, $password ) : $this->ldapClient->bind();
	}

	/**
	 * Get user base DN
	 *
	 * @return string
	 */
	protected function getUserBaseDN( ): string {
		$dn = $this->getUserConfig( static::USERCONFIG_BASE_DN );
		if ( $dn ) {
			return $dn;
		}

		$rdn = $this->getUserConfig( static::USERCONFIG_BASE_RDN );
		$bdn = $this->ldapClient->getBaseDN();
		if ( $bdn ) {
			return $rdn . ',' . $bdn;
		} else {
			return $rdn;
		}
	}

	/**
	 * Get DN for LDAP username.
	 *
	 * @param string $username         Username used for binding
	 * @param Message &$errorMessage   Error message to show the user
	 * @return string|null             Corresponding LDAP DN if successful
	 */
	protected function lookupLDAPUser( string $username, ?Message &$errorMessage ): ?string {
		$errorMessage = null;
		$bindAttr = $this->getUserConfig( static::USERCONFIG_BIND_ATTR );

		if ( $bindAttr ) {
			$baseDN = $this->getUserBaseDN();
			$escapedUsername = LDAPClient::escape($username);
			$dn = "{$bindAttr}={$escapedUsername}," . $baseDN;
		} else {
			$searchAttr = $this->getConfig( static::USERCONFIG_SEARCH_ATTR, 'uid' );
			$attributes = [ 'dn' ];
			try {
				$result = $this->searchLDAPUser( [ $searchAttr => $username ], $attributes );
			} catch ( Exception $ex ) {
				$this->logger->error( 'Error searching userinfo for {username}', [
					'username' => $username, 'exception' => $ex,
				] );
				$errorMessage = wfMessage(
					'ext.hybridauth.authentication.userinfo-error', $this->domain
				);
				$result = null;
			}
			$dn = $result ? $result["dn"] : null;
		}
		return $dn;
	}

	/**
	 * Get LDAP username for DN
	 *
	 * @param string $dn
	 */
	protected function reverseLookupLDAPUser( string $dn ): ?string {
		$bindAttr = $this->getUserConfig( static::USERCONFIG_BIND_ATTR );
		if ( $bindAttr ) {
			$dnParts = $this->ldapClient->parseDN( $dn );
			if ( isset( $dnParts[$bindAttr] ) && $dnParts[$bindAttr] ) {
				return $dnParts[$bindAttr][0];
			}
			$searchAttr = $bindAttr;
		} else {
			$searchAttr = $this->getUserConfig( static::USERCONFIG_SEARCH_ATTR );
		}
		$ldapUser = $this->getLDAPUser( $dn, [ $searchAttr ] );
		if ( !$ldapUser || !isset( $ldapUser[$searchAttr] ) || !$ldapUser[$searchAttr] ) {
			return null;
		}
		return $ldapUser[$searchAttr][0];
	}


	/*
	 * Read a single user on LDAP.
	 *
	 * @param string$dn               User DN to read
	 * @param array|null $attributes  Attributes to return
	 * @return array|null             The requested attributes if successful
	 */
	public function getLDAPUser( string $dn, ?array $attributes ): ?array {
		$searchFilter = $this->getConfig( static::USERCONFIG_SEARCH_FILTER );
		$filters = $searchFilter ? [ $searchFilter ] : null;
		return $this->ldapClient->read( $dn, $attributes, $filters );
	}

	/*
	 * Modify a single LDAP user's attributes
	 * @param string $dn            User DN to modify
	 * @param array  $attrs         New attributes with values
	 * @return bool                 Whether the modification was successful
	 */
	public function modifyLDAPUser( string $dn, array $attributes ): bool {
		return $this->ldapClient->modify( $dn, $attributes );
	}

	/*
	 * Search a single user on LDAP.
	 *
	 * @param array $filters          Filters to apply
	 * @param array|null $attributes  Attributes to return
	 * @return array|null             The requested attributes if successful
	 */
	protected function searchLDAPUser( array $filter, ?array $attributes ): ?array {
		$users = $this->searchLDAPUsers( $filter, $attributes );
		if ( !is_array( $users ) ) {
			return null;
		}
		if ( count( $users ) > 1 ) {
			$this->logger->notice( "User query returned more than one result (filter: {$filter})" );
		}
		if ( count( $users ) !== 1 ) {
			return null;
		}
		return $users[0];
	}

	/**
	 * Search users on LDAP.
	 *
	 * @param array $filters          Filters to apply
	 * @param array|null $attributes  Attributes to return
	 * @return array|null             The requested attributes if successful
	 */
	protected function searchLDAPUsers( array $filter, ?array $attributes ): ?array {
		$searchDN = $this->getUserBaseDN();
		$searchFilter = $this->getConfig( static::USERCONFIG_SEARCH_FILTER );
		if ( $searchFilter ) {
			$filter[] = $searchFilter;
		}
		return $this->ldapClient->search( $attributes, $filter, $searchDN );
	}
}
