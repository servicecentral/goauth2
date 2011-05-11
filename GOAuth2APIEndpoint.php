<?php

	include 'GOAuth2.php';

	class GOAuth2APIEndpoint {

		// How long, in seconds, before a API request's timestamp will go out of date.
		protected $timestamp_limit;

		// The types of access token this API accepts.
		protected $token_types = array(
			GOAuth2::TOKEN_TYPE_MAC
		);

		// The types of HMAC algorithms this API accepts. The first is default.
		// If the MAC token type is supported, there MUST be at least one entry
		// in this array.
		protected $hmac_algorithms = array(
			GOAuth2::HMAC_SHA1,
			GOAuth2::HMAC_SHA256
		);

		/**
		 * Class constructor.
		 *
		 * @param int $timestamp_limit	How long, in seconds, before a API request's timestamp
		 * 								will go out of date. Defaults to 30.
		 *
		 * @return GOAuth2APIEndpoint
		 */
		public function __construct($timestamp_limit = 30) {
			$this->timestamp_limit = $timestamp_limit;

			// Check that at least one algorithm is specified if MAC tokens supported.
			if(in_array(GOAuth2::TOKEN_TYPE_MAC, $this->token_types)) {
				if(count($this->hmac_algorithms) < 1) {
					throw new Exception('GOAuth2APIEndpoint configured to accept MAC tokens, but not HMAC algorithms are specified.');
				}
			}
		}

		/**
		 * Authenticate a HTTP request based on the API's configuration.
		 *
		 * @param   String	$request_uri			The URI of the originating request.
		 * @param	String	$request_method			The HTTP method of the request.
		 * @param 	array 	$params					The POST or GET parameters of the request.
		 * @param 	String	$authorization_header	The contents of the Authorization HTTP header of the request.
		 * @return	Bool							True if authentication valid, False otherwise.
		 */
		public function authenticateRequest($request_uri, $request_method, $params, $authorization_header) {

			// Check that the authorization header contains something we know about
			if(preg_match('/^(BEARER|MAC)\s+(.+?)$/', $authorization_header, $matches) !== 1) {
				throw new GOAuth2InvalidClientException(GOAuth2::ERROR_INVALID_CLIENT);
			}

			// Pull the authorization type and params from the header
			$authorization_type 	= $matches[1];
			$authorization_params 	= $matches[2];

			// Check we support this token type
			if(!in_array(strtolower($authorization_type), $this->token_types)) {
				throw new GOAuth2InvalidClientException(GOAuth2::ERROR_INVALID_REQUEST);
			}

			switch($authorization_type) {
				case 'BEARER':
					// Bearer token.
					$this->authenticateBearerAccessToken($authorization_params);
					break;
				case 'MAC':
					// MAC token.
					$this->authenticateMACAccessToken($request_uri, $request_method, $params, $authorization_params);
					break;
			}

			// Authentication was successful.
			return true;
		}


		/**
		 * Authenticate a bearer token.
		 * @param String $authorization_params
		 */
		protected function authenticateBearerAccessToken($authorization_params) {
			// In this case, the authorization param _is_ the token. Just check it exists.
			$token = $this->getAccessToken($authorization_params);
			if(!$token) {
				throw new GOAuth2UnauthorizedClientException(GOAuth2::ERROR_UNAUTHORIZED_CLIENT);
			}
		}


		/**
		 * Check that the MAC token given in the request is valid and has validly signed the request.
		 *
		 * @param   String		$request_uri			The URI of the originating request.
		 * @param	String		$request_method			The HTTP method of the request.
		 * @param 	array		$params					The parameters of the request.
		 * @param	String		$authorization_string	The contents of the authorization header.
		 * @return	Bool		True if authenticated, False otherwise.
		 */
		private function authenticateMACAccessToken($request_uri, $request_method, $params, $authorization_string) {

			// Expand the parameters in the authorization string
			preg_match_all('/(\w+)="(.+?)"/', $authorization_string, $auth_params);
			foreach($auth_params[1] as $param_index => $param_name) {
				$$param_name = $auth_params[2][$param_index];
			}

			// Check that all required parameters were supplied
			$required_authorization_parameters = array('token', 'timestamp', 'nonce', 'signature');
			foreach($required_authorization_parameters as $param) {
				if(!isset($$param)) {
					throw new GOAuth2InvalidRequestException(GOAuth2::ERROR_INVALID_REQUEST);
				}
			}

			error_log("$authorization_string");
			error_log("$token $timestamp $nonce $signature");

			// Attempt to store this nonce, checking for duplicates in the process.
			if(!$this->storeNonce($token, $nonce)) {
				throw new GOAuth2UnauthorizedClientException(GOAuth2::ERROR_UNAUTHORIZED_CLIENT);
			}

			// Check the timestamp on the request
			if(($timestamp + $this->timestamp_limit) < $this->getTime()) {
				throw new GOAuth2UnauthorizedClientException(GOAuth2::ERROR_UNAUTHORIZED_CLIENT);
			}

			// Get the GOAuth2AccessToken specified by the authorization header
			$token = $this->getAccessToken($token);

			error_log(print_r($token, true));

			if(!$token) {
				throw new GOAuth2UnauthorizedClientException(GOAuth2::ERROR_UNAUTHORIZED_CLIENT);
			}

			// Generate the signature at the server side using the input parameters
			if($token->algorithm && in_array($token->algorithm, $this->hmac_algorithms)) {
				$hmac_algorithm = $token->algorithm;
			} else {
				$hmac_algorithm = $this->hmac_algorithms[0];
			}
			$check_signature = GOAuth2::generateHMACSignature($request_uri, $token->access_token, $token->secret, $timestamp, $nonce, $request_method, $hmac_algorithm);

			// Check that the generated signature is the same as that supplied in the authorization header
			if($signature !== $check_signature) {
				throw new GOAuth2UnauthorizedClientException(GOAuth2::ERROR_UNAUTHORIZED_CLIENT);
			}

			// Authorization succeeded
			return true;
		}


		/**
		 * Get an access token by the access token string.
		 *
		 * This function MUST be reimplemented in any inheriting API subclass.
		 *
		 *
		 * @param 	String 				$access_token
		 * @return	GOAuth2AccessToken	An access token if found, or null otherwise.
		 */
		protected function getAccessToken($access_token) {
			throw new Exception('GOAuth2APIEndpoint::getAccessToken() not implemented!');
		}


		/**
		 * Attempt to store a nonce against a particular token. This function
		 * should return false if the token-nonce combination already exists
		 * in the database.
		 *
		 * This function MUST be reimplemented in any inheriting API subclass.
		 *
		 * @param 	String $token	The Access token string.
		 * @param 	String $nonce	The nonce.
		 *
		 * @return	Bool			True if the nonce was not already stored and was successfully
		 * 							stored, False otherwise.
		 */
		protected function storeNonce($token, $nonce) {
			throw new Exception('GOAuth2APIEndpoint::storeNonce() not implemented!');
		}


		/**
		 * Get the current UNIX timestamp to base timestamp calculations on.
		 * @return int	The UNIX timestamp.
		 */
		protected function getTime() {
			return time();
		}

	}