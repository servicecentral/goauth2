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

		const HMAC_SHA1						= 'hmac-sha-1';
		const HMAC_SHA256					= 'hmac-sha-256';

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
		public $secret;
		public $algorithm;

		public function __construct($access_token, $token_type, $expires_in = null, $refresh_token = null, $scope = null, $secret = null, $algorithm = null) {
			$this->access_token 	= $access_token;
			$this->token_type 		= $token_type;
			$this->expires_in 		= $expires_in;
			$this->refresh_token	= $refresh_token;
			$this->scope 			= $scope;
			$this->secret			= $secret;
			$this->algorithm		= $algorithm;
		}

		public function toJSON() {

			$token = array(
				'access_token' 	=> $this->access_token,
				'token_type'	=> $this->token_type
			);

			// Add optional parameters if set.
			$optional_params = array('expires_in', 'refresh_token', 'scope', 'secret', 'algorithm');
			foreach($optional_params as $param) {
				if(isset($this->$param)) {
					$token[$param] = $this->$param;
				}
			}

			return json_encode($token);
		}
	}


	/**
	 * A HTTP Request.
	 * @package	GOAuth2
	 */
	class GOAuthHttpRequest {
		public $authorization_header;
		public $method;
		public $uri;
		public $params;
		public $expect_json;

		public function __construct($uri, $method = 'POST', $params = array(), $expect_json = false, $authorization_header = null) {
			$this->uri 					= $uri;
			$this->method 				= $method;
			$this->params 				= $params;
			$this->expect_json 			= $expect_json;
			$this->authorization_header	= $authorization_header;
		}

		/**
		 * Get the signature of this request for use with signature-based
		 * token mechanisms, as set out in s3.3.1 of the OAuth 2.0 MAC Token
		 * specification (draft v2).
		 *
		 * @param GOAuth2AccessToken 	$token		The token being used to sign the request.
		 * @param int					$timestamp	A unix timestamp.
		 * @param String				$nonce		A nonce for this request.
		 */
		public function getSignature(GOAuth2AccessToken $token, $timestamp, $nonce) {

			// Normalise request. First break the URI into its component parts.
			$parsed_uri 			= parse_url($this->uri);
			$parsed_uri['scheme']	= isset($parsed_uri['scheme']) ? strtolower($parsed_uri['scheme']) : 'http';
			$parsed_uri['port']		= isset($parsed_uri['port']) ? $parsed_uri['port'] : (($parsed_uri['scheme'] == 'https') ? 443 : 80);

			$request_parts 			= array();
			$request_parts[] 		= $token->access_token;
			$request_parts[] 		= $timestamp;
			$request_parts[] 		= $nonce;
			$request_parts[] 		= ''; // The 'body hash' - not currently using it.
			$request_parts[] 		= strtoupper($this->method);
			$request_parts[]		= strtolower($parsed_uri['host']);
			$request_parts[]		= $parsed_uri['port'];
			$request_parts[]		= $parsed_uri['path'];

			// Normalize the query parameters
			$query_parts			= isset($parsed_uri['query']) ? explode('&', urldecode($parsed_uri['query'])) : array();
			$encoded_query_parts	= array();
			foreach($query_parts as $query_part) {

				// Extract the parameter and its value
				if(($ep = strpos($query_part, '=')) !== false) {
					$param = substr($query_part, 0, $ep);
					$value = substr($query_part, $ep + 1);
				} else {
					$param = $query_part;
					$value = '';
				}

				// Append the "param="value" to the return array, with URL-encoding.
				// The OAuth MAC spec requires spaces to be %20-ed rather than +-encoded.
				$encoded_query_parts[] = str_replace('+', '%20', urlencode($param)) . '=' . str_replace('+', '%20', urlencode($value));
			}

			// Order the query parts and append to the overall array
			sort($encoded_query_parts);
			$request_parts = array_merge($request_parts, $encoded_query_parts);

			// Implode the request with newline characters and add a trailing newline
			$normalized_request	= implode("\n", $request_parts) . "\n";

			// Convert the OAuth-specified algorithm name to the version used by PHP's hash_hmac
			switch($token->algorithm) {
				case GOAuth2::HMAC_SHA1:
					$hash_hmac_algorithm = 'sha1';
					break;
				case GOAuth2::HMAC_SHA256:
					$hash_hmac_algorithm = 'sha256';
					break;
				default:
					throw new GOAuth2Exception('unknown_algorithm', 'Unknown algorithm passed to getSignature().');
			}

			// Generate the signature
			$signature = hash_hmac($hash_hmac_algorithm, $normalized_request, $token->secret, $raw_output = true);

			// Base64-encode the signature and return.
			return base64_encode($signature);
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

	// Thrown when a connection could not be established.
	class GOAuth2ConnectionException extends GOAuth2Exception {}

	// Thrown when the response from the server is invalid.
	class GOAuth2InvalidResponseException extends GOAuth2Exception {}

	// Thrown when a call attempt is made without an active token
	class GOAuth2NoActiveTokenException extends GOAuth2Exception {}

	/* The following Exception types mirror the errors that may be returned
	 * by an OAuth2.0 Token Server as defined s5.2 of the specification. */
	class GOAuth2InvalidRequestException extends  GOAuth2Exception {}
	class GOAuth2InvalidClientException extends  GOAuth2Exception {}
	class GOAuth2InvalidGrantException extends  GOAuth2Exception {}
	class GOAuth2UnauthorizedClientException extends  GOAuth2Exception {}
	class GOAuth2UnsupportedGrantTypeException extends  GOAuth2Exception {}
	class GOAuth2InvalidScopeException extends  GOAuth2Exception {}


	/**
	 * A handy function to avoid verbose $a = isset($b) ? $b : null statements.
	 *
	 * @param mixed $var
	 * @param mixed $ifnot
	 */
	function ifset($var, $ifnot = null) {
		return isset($var) ? $var : $ifnot;
	}