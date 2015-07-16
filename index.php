<?php

/* -AFTERLOGIC LICENSE HEADER- */

class_exists('CApi') or die();

class CLdapAuthPlugin extends AApiPlugin
{
	/**
	 * @var string
	 */
	private $sHost;

	/**
	 * @var int
	 */
	private $iPort;

	/**
	 * @var string
	 */
	private $sBindDn;

	/**
	 * @var string
	 */
	private $sPassword;

	/**
	 * @var string
	 */
	private $sUsersDn;

	/**
	 * @var string
	 */
	private $sLoginLDAPField;

	/**
	 * @var string
	 */
	private $sEmailLDAPField;
	
	/**
	 * @param CApiPluginManager $oPluginManager
	 */
	public function __construct(CApiPluginManager $oPluginManager)
	{
		parent::__construct('1.0', $oPluginManager);

		$sConfigPrefix = 'plugins.ldap-auth.config.';
		$this->sHost = CApi::GetConf($sConfigPrefix.'host', '127.0.0.1');
		$this->iPort = CApi::GetConf($sConfigPrefix.'port', 389);
		$this->sBindDn = CApi::GetConf($sConfigPrefix.'bind-dn', '');
		$this->sPassword = CApi::GetConf($sConfigPrefix.'password', '');
		$this->sUsersDn = CApi::GetConf($sConfigPrefix.'users-dn', '');

		$this->sLoginLDAPField = CApi::GetConf($sConfigPrefix.'login-field', 'login');
		$this->sEmailLDAPField = CApi::GetConf($sConfigPrefix.'email-field', 'email');

		$this->AddHook('api-integrator-login-to-account', 'ApiIntegratorLoginToAccount');
	}

	/**
	 * @staticvar CLdapConnector|null $oLdap
	 * @return CLdapConnector|bool
	 */
	private function Ldap()
	{
		static $oLdap = null;
		if (null === $oLdap)
		{
			CApi::Inc('common.ldap');

			$oLdap = new CLdapConnector($this->sUsersDn);
			$oLdap = $oLdap->Connect($this->sHost, $this->iPort, $this->sBindDn, $this->sPassword) ? $oLdap : false;
		}

		return $oLdap;
	}	
	
	/**
	 * @param string $sEmail
	 * @param string $sPassword
	 * @param string $sLogin
	 * @param string $sLanguage
	 * @param string $bAuthResult
	 */
	public function ApiIntegratorLoginToAccount(&$sEmail, &$sPassword, &$sLogin, &$sLanguage, &$bAuthResult)
	{
		if (function_exists('ldap_connect'))
		{
			if (0 < strlen($sLogin) && 0 < strlen($sPassword))
			{
				$oLdap = $this->Ldap();

				if ($oLdap && $oLdap->Search('('. $this->sLoginLDAPField .'='.$sLogin.')') && 1 === $oLdap->ResultCount())
				{
					$aData = $oLdap->ResultItem();
					$sDn = !empty($aData['dn']) ? $aData['dn'] : '';

					if (!empty($sDn) && $oLdap->ReBind($sDn, $sPassword))
					{
						if (isset($aData[$this->sEmailLDAPField]))
						{
							if (isset($aData[$this->sEmailLDAPField]['count']))
							{
								$sEmail = !empty($aData[$this->sEmailLDAPField][0]) ? $aData[$this->sEmailLDAPField][0] : '';
							}
							else
							{
								$sEmail = $aData[$this->sEmailLDAPField];
							}
						}
						$bAuthResult = true;
						return;
					}
				}
			}			
		}
		else
		{
			CApi::Log('Ldap: ldap extension are not available in your PHP configuration!', ELogLevel::Error);
		}

		throw new CApiManagerException(Errs::WebMailManager_AccountAuthentication);
	}

}

return new CLdapAuthPlugin($this);
