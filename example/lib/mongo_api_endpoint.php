<?php

	class MongoAPIEndpoint extends GOAuth2APIEndpoint {

		private $mongo;

		public function __construct() {
			parent::__construct();
			$m = new Mongo();
			$this->mongo = $m->goauth2;
		}

		/**
		 * Get an Access Token by access token string.
		 * @see GOAuth2APIEndpoint::getAccessToken()
		 */
		protected function getAccessToken($access_token) {
			$token = $this->mongo->tokens->findOne(array("token" => $access_token));

			if(!$token) {
				return null;
			}

			return new GOAuth2AccessToken(
				$token["token"],
				GOAuth2::TOKEN_TYPE_MAC,
				$token["expires"],
				$refresh = null,
				$token["scopes"],
				$token["secret"]
			);
		}

		/**
		 * Check a none for existence and store otherwise.
		 * @see GOAuth2APIEndpoint::storeNonce()
		 */
		protected function storeNonce($token, $nonce) {
			$nonce = array("token" => $token, "nonce" => $nonce);

			$existing_nonce = $this->mongo->nonces->findOne($nonce);
			if($existing_nonce) {
				return false;
			}

			$this->mongo->nonces->insert($nonce);
			return true;
		}

	}