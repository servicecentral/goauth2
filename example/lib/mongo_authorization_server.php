<?php

	class MongoAuthorizationServer extends GOAuth2AuthorizationServer {

		private $mongo;

		public function __construct() {
			parent::__construct($enforce_ssl = false);
			$m = new Mongo();
			$this->mongo = $m->goauth;
		}

		/**
		 * Check whether the specified client exists.
		 * @see GOAuth2AuthorizationServer::validateClient()
		 */
		protected function validateClient($client_id) {
			return ($this->mongo->clients->findOne(array("client_id" => $client_id) !== null));
		}

		/**
		 * Generate and store a new Authorization code for the given client.
		 * @see GOAuth2AuthorizationServer::generateNewAuthorizationCode()
		 */
		protected function generateNewAuthorizationCode($client_id, $redirect_uri, $user, $scope) {
			$code = md5(uniqid());

			$this->mongo->codes->insert(array(
				"client_id" 	=> $client_id,
				"redirect_uri" 	=> $redirect_uri,
				"user" 			=> $user,
				"scopes" 		=> array_filter(explode(' ', $scope)),
				"code"			=> $code
			));

			return new GoAuth2AuthorizationCode($code, $redirect_uri);
		}

	}