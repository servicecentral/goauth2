<?php

	/**
	 * The GOAuth2 class contains a number of fundamental constants
	 * for use with the OAuth2.0 specification.
	 * @package GOAuth2
	 */
	class GOAuth2 {

		const SERVER_AUTH_TYPE_CREDENTIALS	= 0;
		const SERVER_AUTH_TYPE_HTTP_BASIC	= 1;
		const SERVER_AUTH_TYPE_ANONYMOUS	= 2;

		const RESPONSE_TYPE_TOKEN 			= 'token';
		const RESPONSE_TYPE_CODE			= 'code';

		const GRANT_TYPE_CODE 				= 'authorization_code';
		const GRANT_TYPE_CLIENT_CREDENTIALS	= 'client_credentials';
		const GRANT_TYPE_PASSWORD 			= 'password';
		const GRANT_TYPE_REFRESH_TOKEN		= 'refresh_token';

		const ERROR_INVALID_REQUEST			= 'invalid_request';
		const ERROR_INVALID_CLIENT			= 'invalid_client';
		const ERROR_INVALID_GRANT			= 'invalid_grant';
		const ERROR_UNAUTHORIZED_CLIENT		= 'unauthorized_client';
		const ERROR_UNSUPPORTED_GRANT_TYPE	= 'unsupported_grant_type';
		const ERROR_INVALID_SCOPE			= 'invalid_scope';

		const TOKEN_TYPE_BEARER				= 'bearer';
		const TOKEN_TYPE_MAC				= 'mac';

		const HTTP_200 = 'HTTP/1.1 200 OK';
		const HTTP_301 = 'HTTP/1.1 301 Moved Permanantly';
		const HTTP_400 = 'HTTP/1.1 400 Bad Request';
		const HTTP_401 = 'HTTP/1.1 401 Unauthorized';
		const HTTP_403 = 'HTTP/1.1 403 Forbidden';
		const HTTP_404 = 'HTTP/1.1 404 File Not Found';
		const HTTP_410 = 'HTTP/1.1 410 Gone';
		const HTTP_500 = 'HTTP/1.1 500 Internal Server Error';
		const HTTP_503 = 'HTTP/1.1 503 Service Unavailable';

		const CONTENT_TYPE_JSON = 'application/json';

		private static $error_descriptions = array(
			self::ERROR_INVALID_REQUEST => 'The request is missing a required parameter, includes an unsupported parameter or parameter value, repeats a parameter, includes multiple credentials, utilizes more than one mechanism for authenticating the client, or is otherwise malformed.',
			self::ERROR_INVALID_CLIENT 	=> 'Client authentication failed.'
		);

		public static function getErrorDescription($error) {
			return self::$error_descriptions[$error];
		}
	}


	/**
	 * An OAuth2.0-compliant access token.
	 * @package	GOAuth2
	 */
	class GOAuth2AccessToken {

		public $access_token;
		public $token_type;
		public $expires_in;
		public $refresh_token;
		public $scope;

		public function __construct($access_token, $token_type, $expires_in = null, $refresh_token = null, $scope = null) {
			$this->access_token 	= $access_token;
			$this->token_type 		= $token_type;
			$this->expires_in 		= $expires_in;
			$this->refresh_token	= $refresh_token;
			$this->scope 			= $scope;
		}

		public function toJSON() {

			$token = array(
				'access_token' 	=> $this->access_token,
				'token_type'	=> $this->token_type
			);

			if(isset($this->expires_in)) {
				$token['expires_in'] = $this->expires_in;
			}

			if(isset($this->refresh_token)) {
				$token['refresh_token'] = $this->refresh_token;
			}

			if(isset($this->scope)) {
				$token['scope'] = $this->scope;
			}

			return json_encode($token);
		}
	}


	/**
	 * A HTTP Request.
	 * @package	GOAuth2
	 */
	class GOAuthHttpRequest {
		public $method;
		public $uri;
		public $params;
		public $expect_json;

		public function __construct($uri, $method = 'POST', $params = array(), $expect_json = false) {
			$this->uri 			= $uri;
			$this->method 		= $method;
			$this->params 		= $params;
			$this->expect_json 	= $expect_json;
		}
	}


	/**
	 * A HTTP Response.
	 * @package GOAuth2
	 */
	class GOAuthHttpResponse {
		public $status_code;
		public $headers;
		public $response;
	}


	/**
	 * The base Exception class for all GOAuth2 exceptions.
	 * @package GOAuth2
	 */
	class GOAuth2Exception extends Exception {
		public function __construct($error, $error_description = null, $error_uri = null) {
			$this->error 				= $error;
			$this->error_description 	= $error_description;
			$this->error_uri 			= $error_uri;
		}

		public function getError() { return $this->error; }
		public function getDescription() { return $this->error_description; }
		public function getURI() { return $this->error_uri; }
	}

	class GOAuth2TokenRequestException extends GOAuth2Exception {}

	/**
	 * A handy function to avoid verbose $a = isset($b) ? $b : null statements.
	 *
	 * @param mixed $var
	 * @param mixed $ifnot
	 */
	function ifset($var, $ifnot = null) {
		return isset($var) ? $var : $ifnot;
	}