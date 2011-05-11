<?php

	/**
	 * The GOAuth2 class contains a number of fundamental constants
	 * for use with the OAuth2.0 specification.
	 * @package GOAuth2
	 */
	class GOAuth2 {

		const SERVER_AUTH_TYPE_CREDENTIALS		= 'credentials';
		const SERVER_AUTH_TYPE_HTTP_BASIC		= 'basic';
		const SERVER_AUTH_TYPE_ANONYMOUS		= 'anonymous';

		const RESPONSE_TYPE_TOKEN 				= 'token';
		const RESPONSE_TYPE_CODE				= 'code';

		const GRANT_TYPE_CODE 					= 'authorization_code';
		const GRANT_TYPE_CLIENT_CREDENTIALS		= 'client_credentials';
		const GRANT_TYPE_PASSWORD 				= 'password';
		const GRANT_TYPE_REFRESH_TOKEN			= 'refresh_token';

		const ERROR_INVALID_REQUEST				= 'invalid_request';
		const ERROR_INVALID_CLIENT				= 'invalid_client';
		const ERROR_INVALID_GRANT				= 'invalid_grant';
		const ERROR_UNAUTHORIZED_CLIENT			= 'unauthorized_client';
		const ERROR_UNSUPPORTED_GRANT_TYPE		= 'unsupported_grant_type';
		const ERROR_INVALID_SCOPE				= 'invalid_scope';
		const ERROR_ACCESS_DENIED				= 'access_denied';
		const ERROR_UNSUPPORTED_RESPONSE_TYPE 	= 'unsupported_response_type';

		// These errors are NOT defined by the OAuth2.0 protocol
		const ERROR_INTERNAL_ERROR				= 'internal_error';
		const ERROR_INVALID_REDIRECT_URI		= 'invalid_redirect_uri';

		const TOKEN_TYPE_BEARER					= 'bearer';
		const TOKEN_TYPE_MAC					= 'mac';

		const HMAC_SHA1							= 'hmac-sha-1';
		const HMAC_SHA256						= 'hmac-sha-256';

		const HTTP_200 							= 'HTTP/1.1 200 OK';
		const HTTP_301 							= 'HTTP/1.1 301 Moved Permanantly';
		const HTTP_302							= 'HTTP/1.1 302 Found';
		const HTTP_400 							= 'HTTP/1.1 400 Bad Request';
		const HTTP_401 							= 'HTTP/1.1 401 Unauthorized';
		const HTTP_403 							= 'HTTP/1.1 403 Forbidden';
		const HTTP_404 							= 'HTTP/1.1 404 File Not Found';
		const HTTP_410 							= 'HTTP/1.1 410 Gone';
		const HTTP_500 							= 'HTTP/1.1 500 Internal Server Error';
		const HTTP_503 							= 'HTTP/1.1 503 Service Unavailable';

		const CONTENT_TYPE_JSON 				= 'application/json';
		const CONTENT_TYPE_XML 					= 'text/xml';


		/**
		 * Get an error description for the specified code.
		 *
		 * @param 	String 	$error
		 * @return	String	An error description.
		 */
		public static function getErrorDescription($error) {
			if(!isset(self::$error_descriptions[$error])) {
				return 'Unknown error.';
			}
			return self::$error_descriptions[$error];
		}

		private static $error_descriptions = array(
			self::ERROR_INVALID_REQUEST 			=> 'The request is missing a required parameter or is otherwise malformed.',
			self::ERROR_INVALID_CLIENT 				=> 'Client authentication failed.',
			self::ERROR_INVALID_GRANT 				=> 'The provided authorization grant is invalid, expired or revoked.',
			self::ERROR_UNAUTHORIZED_CLIENT 		=> 'The authenticated client is not authorized to use the specified grant type.',
			self::ERROR_UNSUPPORTED_GRANT_TYPE 		=> 'The authorization grant type is not supported by this server.',
			self::ERROR_INVALID_SCOPE 				=> 'The requested scope is unknown, invalid, malformed or exceed the permissible scope.',
			self::ERROR_ACCESS_DENIED 				=> 'The resource owner or authorization server denied the request.',
			self::ERROR_UNSUPPORTED_RESPONSE_TYPE 	=> 'The authorization server does not support obtaining an authorization code using this method.',
			self::ERROR_INTERNAL_ERROR 				=> 'An internal server error occured while processing the request.'
		);


		/**
		 * Get the HTTP response status code for the given error.
		 *
		 * @param	String	$error
		 * @return	String	A HTTP response status code.
		 */
		public static function getErrorHttpStatusCode($error) {
			if(!isset(self::$error_http_codes[$error])) {
				return self::HTTP_500; // Internal Server Error
			}
			return self::$error_http_codes[$error];
		}

		private static $error_http_codes = array(
			self::ERROR_INVALID_REQUEST 			=> self::HTTP_400, // Bad Request
			self::ERROR_INVALID_CLIENT 				=> self::HTTP_401, // Unauthorized
			self::ERROR_INVALID_GRANT 				=> self::HTTP_401, // Unauthorized
			self::ERROR_UNAUTHORIZED_CLIENT 		=> self::HTTP_403, // Forbidden
			self::ERROR_UNSUPPORTED_GRANT_TYPE 		=> self::HTTP_400, // Bad Request
			self::ERROR_INVALID_SCOPE 				=> self::HTTP_400, // Bad Request
			self::ERROR_ACCESS_DENIED 				=> self::HTTP_401, // Unauthorized
			self::ERROR_UNSUPPORTED_RESPONSE_TYPE 	=> self::HTTP_400, // Bad Request
			self::ERROR_INTERNAL_ERROR 				=> self::HTTP_500  // Internal Server Error
		);


		/**
		 * Generate a request signature as set out in s3.3.1 of the OAuth 2.0 MAC Token
		 * specification (draft v2).
		 *
		 * @param 	String 	$uri			The URI of the request, including querystring.
		 * @param 	String 	$access_token	The access token string.
		 * @param 	String 	$secret			The access token secret.
		 * @param 	int		$timestamp		The timestamp.
		 * @param 	String	$nonce			The nonce.
		 * @param 	String	$http_method	Optional. The HTTP method of the request. Defaults to 'POST'.
		 * @param 	String	$algorithm		Optional. The algorithm to use. Defaults to SHA1.
		 * @return	String	A base64-encoded signature string.
		 */
		public static function generateHMACSignature($uri, $access_token, $secret, $timestamp, $nonce, $http_method = 'POST', $algorithm = GOAuth2::HMAC_SHA1) {

			// Normalise request. First break the URI into its component parts.
			$parsed_uri 			= parse_url($uri);
			$parsed_uri['scheme']	= isset($parsed_uri['scheme']) ? strtolower($parsed_uri['scheme']) : 'http';
			$parsed_uri['port']		= isset($parsed_uri['port']) ? $parsed_uri['port'] : (($parsed_uri['scheme'] == 'https') ? 443 : 80);

			$request_parts 			= array(
				$access_token,						// The access token used for the request.
				$timestamp,							// The timestamp for the request.
				$nonce,								// The unique 'number used once' for the request.
				'',									// The body hash for the request. Currently not used.
				strtoupper($http_method),			// The HTTP metod (eg 'POST' or 'GET')
				strtolower($parsed_uri['host']),	// The URI hostname (eg example.com)
				$parsed_uri['port'],				// The port of the request (eg 80)
				$parsed_uri['path'],				// The path of the request (eg '/api/v1')
			);

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
			switch($algorithm) {
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
			$signature = hash_hmac($hash_hmac_algorithm, $normalized_request, $secret, $raw_output = true);

			// Base64-encode the signature and return.
			return base64_encode($signature);
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


		/**
		 * Access Token Constructor.
		 *
		 * @param 	String 	$access_token	The access token string.
		 * @param 	String 	$token_type		The type of the token (such as 'mac' or 'bearer')
		 * @param 	int		$expires_in		Optional. The number of seconds until this token expires.
		 * @param 	String 	$refresh_token	Optional. The refresh token string.
		 * @param 	String 	$scope			Optional. A space-delimited string listing scopes this token is valid for.
		 * @param 	String 	$secret			Optional. The token secret string.
		 * @param 	String 	$algorithm		Optional. The algorithm that should be used with this token to generate signatures.
		 * @return	GOAuth2AccessToken
		 */
		public function __construct($access_token, $token_type, $expires_in = null, $refresh_token = null, $scope = null, $secret = null, $algorithm = null) {
			$this->access_token 	= $access_token;
			$this->token_type 		= $token_type;
			$this->expires_in 		= $expires_in;
			$this->refresh_token	= $refresh_token;
			$this->scope 			= $scope;
			$this->secret			= $secret;
			$this->algorithm		= $algorithm;
		}


		/**
		 * Return a JSON string representing this access token.
		 * @return	String	A JSON-formatted string.
		 */
		public function toJSON() {

			// Set the required parameters
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

			// Return the JSON encoding
			return json_encode($token);
		}
	}


	class GOAuth2AuthorizationCode {
		public $code;
		public $redirect_uri;

		public function __construct($code, $redirect_uri) {
			$this->code = $code;
			$this->redirect_uri = $redirect_uri;
		}

		public function toJSON() {
			return json_encode(array(
				'code' 			=> $this->code,
				'redirect_uri'	=> $this->redirect_uri
			));
		}
	}


	/**
	 * A HTTP Request.
	 * @package	GOAuth2
	 */
	class GOAuth2HttpRequest {
		public $authorization_header;
		public $method;
		public $uri;
		public $params;

		public function __construct($uri, $method = 'POST', $params = array(), $authorization_header = null) {
			$this->uri 					= $uri;
			$this->method 				= $method;
			$this->params 				= $params;
			$this->authorization_header	= $authorization_header;
		}
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
	class GOAuth2ConnectionException 			extends GOAuth2Exception {}

	// Thrown when the response from the server is invalid.
	class GOAuth2InvalidResponseException 		extends GOAuth2Exception {}

	// Thrown when a call attempt is made without a token.
	class GOAuth2NoTokenException 				extends GOAuth2Exception {}

	/* The following Exception types mirror the errors that may be returned
	 * by an OAuth2.0 Token Server as defined s5.2 of the specification. */
	class GOAuth2InvalidRequestException 		extends  GOAuth2Exception {}
	class GOAuth2InvalidClientException 		extends  GOAuth2Exception {}
	class GOAuth2InvalidGrantException 			extends  GOAuth2Exception {}
	class GOAuth2UnauthorizedClientException 	extends  GOAuth2Exception {}
	class GOAuth2UnsupportedGrantTypeException 	extends  GOAuth2Exception {}
	class GOAuth2InvalidScopeException 			extends  GOAuth2Exception {}
	class GOAuth2InvalidRedirectURIException 	extends  GOAuth2Exception {}
	class GOAuth2SSLException					extends	 GOAuth2Exception {}