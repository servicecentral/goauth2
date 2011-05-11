<?php

	class MongoTokenServer extends GOAuth2TokenServer {

		private $mongo;

		private $scopes = array(
			'scope_a',
			'scope_b',
			'scope_c'
		);

		public function __construct() {
			parent::__construct($token_type = GOAuth2::TOKEN_TYPE_MAC, GOAuth2::SERVER_AUTH_TYPE_CREDENTIALS, $enforce_ssl = false);
			$m = new Mongo();
			$this->mongo = $m->goauth2;
		}

		/**
		 * Check that the given client ID and client secret exists.
		 * @see GOAuth2TokenServer::authenticateClientCredentials()
		 */
		protected function authenticateClientCredentials($client_id, $client_secret) {
			$client = $this->mongo->clients->findOne(array("client_id" => $client_id, "client_secret" => $client_secret));
			return ($client !== null);
		}

		/**
		 * Generate a new access token
		 * @see GOAuth2TokenServer::generateAccessToken()
		 */
		protected function generateAccessToken($client_id, $user = null, $scope = null) {
			$token 		= md5(uniqid());
			$secret		= md5(uniqid());
			$this->mongo->tokens->insert(array(
				"client_id" 	=> $client_id,
				"user" 			=> $user,
				"scopes" 		=> $scope ? array_filter(explode(' ', $scope)) : array(),
				"token"			=> $token,
				"expires"		=> time() + 86400,
				"secret"		=> $secret
			));

			return new GOAuth2AccessToken($token, $this->token_type, $expires_in = 86400, $refresh = null, $scope, $secret);
		}

		/**
		 * Generate a new access token from an access code
		 * @see GOAuth2TokenServer::generateAccessTokenFromAuthorizationCode()
		 */
		protected function generateAccessTokenFromAuthorizationCode($code) {
			$code = $this->mongo->codes->findOne(array("code" => $code));

			// If the code wasn't valid, return an error.
			if(!$code) { $this->sendErrorResponse(GOAuth2::ERROR_INVALID_REQUEST); }

			// Create the new access token
			$token = $this->generateAccessToken($code->client_id, $code->user, $code->scope);

			// Delete the auth code
			$this->mongo->codes->remove(array("code" => $code));

			return $token;
		}

		/**
		 * Validate a given authorization code.
		 * @see GOAuth2TokenServer::validateAuthorizationCode()
		 */
		protected function validateAuthorizationCode($client_id, $code, $redirect_uri) {
			if(!($this->mongo->codes->findOne(array("client_id" => $client_id, "code" => $code, "redirect_uri" => $redirect_uri) !== null))) {
				$this->sendErrorResponse(GOAuth2::ERROR_INVALID_GRANT);
			}
		}

		/**
		 * Check that the specified client is permitted to obtain an access token
		 * of the specified scope for the specified user.
		 * @see GOAuth2TokenServer::checkTokenRequestScope()
		 */
		protected function checkTokenRequestScope($client_id, $user = null, $scope = null) {
			// If the scope's empty, no worries.
			if(!$scope) { return; }

			// Check that all of the scopes specified are valid for us.
			$scopes = array_filter(explode(' ', $scope));
			if(count($scopes) !== count(array_intersect($scopes, $this->scopes))) {
				$this->sendErrorResponse(GOAuth2::ERROR_INVALID_SCOPE);
			}
		}

	}