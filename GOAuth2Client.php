<?php

	require_once 'GOAuth2.php';

	/**
	 * OAuth2.0-compliant client.
	 * @package GOAuth2
	 */
	class GOAuth2Client {

		// Unique ID to identify the client to the service provider.
		protected $client_id;

		// The private secret known only to the client and the service provider.
		protected $client_secret;

		// The URI of the service provider's authorization endpoint.
		protected $authorization_uri;

		// The URI of the service provider's token endpoint.
		protected $token_uri;

		// The Authentication method the token endpoint uses (usually client
		// id / secret but could be something else).
		protected $token_auth_method;

		// A token 'cache' to store any tokens we receive
		private $tokens;
		private $active_token;

		/**
		 * Class constructor.
		 * @param 	String		$client_id
		 * @param 	String		$client_secret
		 * @param	String		$authorization_uri
		 * @param	String		$token_uri
		 * @param	String		$token_auth_method
		 * @param	array		$tokens				Optional. An array of GOAuth2AccessToken objects
		 * 											that may be used by the client.
		 * @return	GOAuth2Client
		 */
		public function __construct($client_id, $client_secret, $authorization_uri, $token_uri, $token_auth_method = GoAuth2::SERVER_AUTH_TYPE_CREDENTIALS, $tokens = array()) {
			$this->client_id 			= $client_id;
			$this->client_secret 		= $client_secret;
			$this->authorization_uri	= $authorization_uri;
			$this->token_uri			= $token_uri;
			$this->token_auth_method	= $token_auth_method;

			// If any tokens were supplied, add them to our internal 'cache'
			if(!empty($tokens)) {
				foreach($tokens as /** @var GOAuth2AccessToken */ $token) {
					$this->tokens[$token->access_token] = $token;

					if(!$this->getActiveToken()) {
						$this->setActiveToken($token->access_token);
					}
				}
			}
		}


		/**
		 * Add a new token to the internal token cache and set it as the
		 * new active token.
		 *
		 * @param GOAuth2AccessToken 	$token
		 * @param Bool					$set_active
		 */
		public function addToken(GOAuth2AccessToken $token, $set_active = true) {
			$this->tokens[$token->access_token] = $token;
			if($set_active) {
				$this->setActiveToken($token->access_token);
			}
		}


		/**
		 * Set the 'active' token to that with the specified access token string.
		 * If an invalid token is specified, False is returned. Otherwise, the
		 * token object is returned.
		 *
		 * @param 	String 	$access_token	The access token's string.
		 * @return	GOAuth2AccessToken		Token object on success, null otherwise.
		 */
		public function setActiveToken($access_token) {
			if(!isset($this->tokens[$access_token])) {
				return null;
			}

			$this->active_token = $access_token;
			return $this->getActiveToken();
		}


		/**
		 * Get the currently active token object, or null if no active token
		 * exists.
		 * @return	GOAuth2AccessToken	Active Token object or null if none active.
		 */
		public function getActiveToken() {
			if(!$this->active_token || !isset($this->tokens[$this->active_token])) {
				return null;
			}
			return $this->tokens[$this->active_token];
		}


		/**
		 * Get a token using the credentials of the resource owner directly.
		 *
		 * @param String	$username	The resource owner's username.
		 * @param String	$password	The resource owner's password.
		 * @param String	$scope		Optional. A space-delimited list
		 * 								describing the scope of the token
		 * 								request.
		 */
		public function getTokenByResourceOwnerCredentials($username, $password, $scope = null) {
			$params = array(
				'grant_type' 	=> GOAuth2::GRANT_TYPE_PASSWORD,
				'username'		=> $username,
				'password'		=> $password
			);

			// Add the scope parameter if non-empty.
			if(!empty($scope)) {
				$params['scope'] = $scope;
			}

			// Construct the token request.
			$token_request = new GOAuth2HttpRequest($this->token_uri, 'POST', $params);

			// Make the token request.
			return $this->makeTokenRequest($token_request);
		}


		/**
		 * Get a token using client credentials only.
		 *
		 * @param	String	$scope	Optional. A space-delimited list describing the
		 * 							scope of the token request.
		 * @return	GoAuth2AccessToken
		 */
		public function getTokenByClientCredentials($scope = null) {

			// Set parameters required for the token request.
			$params = array(
				'grant_type' 	=> GOAuth2::GRANT_TYPE_CLIENT_CREDENTIALS,
				'client_id'		=> $this->client_id,
				'client_secret'	=> $this->client_secret
			);

			// Add the scope parameter if non-empty.
			if(!empty($scope)) {
				$params['scope'] = $scope;
			}

			// Construct the token request.
			$token_request = new GOAuth2HttpRequest($this->token_uri, 'POST', $params);

			// Make the token request.
			return $this->makeTokenRequest($token_request);
		}


		/**
		 * Refresh a held access token.
		 *
		 * @param GOAuth2AccessToken	$token	The held token.
		 * @param String				$scope	Optional. A space-delimited list describing
		 * 										the scope of the token request.
		 */
		public function refreshAccessToken(GOAuth2AccessToken $token, $scope = null) {

			// Set parameters required for the refresh request.
			$params = array(
				'grant_type'	=> GOAuth2::GRANT_TYPE_REFRESH_TOKEN,
				'refresh_token'	=> $token->refresh_token
			);

			// Add the scope parameter if non-empty.
			if(!empty($scope)) {
				$params['scope'] = $scope;
			}

			// Construct and make the refresh request.
			$refresh_request = new GOAuth2HttpRequest($this->token_uri, 'POST', $params);

			// Make the token request.
			return $this->makeTokenRequest($refresh_request);
		}


		/**
		 * Make a request for a token as specified by the request parameter.
		 *
		 * @param 	GOAuth2HttpRequest $request
		 * @throws	GOAuth2TokenException
		 * @return	GOAuth2AccessToken
		 */
		private function makeTokenRequest(GOAuth2HttpRequest $request) {

			// Add authentication parameters as required.
			switch($this->token_auth_method) {
				case GoAuth2::SERVER_AUTH_TYPE_CREDENTIALS:
					// Client credentials (the default authentication method).
					// Add the client ID and client secret to the request.
					$request->params['client_id'] 		= $this->client_id;
					$requent->params['client_secret'] 	= $this->client_secret;
					break;

				case GoAuth2::SERVER_AUTH_TYPE_HTTP_BASIC:
					// HTTP BASIC authentication (not really recommended).
					// Add the BASIC auth details to the Auth header.
					$authorization_string			= base64_encode("{$this->client_id}:{$this->client_secret}");
					$request->authorization_header 	= "Authorization: Basic $authorization_string";
					break;

				case GoAuth2::SERVER_AUTH_TYPE_ANONYMOUS:
				default:
					// Do nothing for anonymous or unknown auth type.
					break;
			}

			// Make the request and get the JSON response.
			$json_response 	= $this->sendRequest($request);
			$response 		= json_decode($json_response);

			// If a known error was returned, throw an exception.
			if(isset($response->error)) {
				$this->handleTokenRequestError($response);
			}

			// Check that what was returned is in fact JSON
			if(!$response || !isset($response->access_token) || !isset($response->token_type)) {
				throw new GOAuth2InvalidResponseException('invalid_response', 'The response from the server was invalid.');
			}

			// Return a new access token object.
			$new_token = new GOAuth2AccessToken(
				$response->access_token,
				$response->token_type,
				isset($response->expires_in) 	? $response->expires_in : null,
				isset($response->refresh_token) ? $response->refresh_token : null,
				isset($response->scope) 		? $response->scope : null,
				isset($response->secret) 		? $response->secret : null,
				isset($response->algorithm) 	? $response->algorithm : null
			);

			// Add this token to our cache
			$this->addToken($new_token);

			return $new_token;
		}


		/**
		 * Throw the correct Exception based on the type of error returned by the token
		 * server.
		 *
		 * @param $response		The stdClass response object from a token request.
		 */
		private function handleTokenRequestError($response) {
			$error				= $response->error;
			$error_description 	= isset($response->error_description) ? $response->error_description : null;
			$error_uri 			= isset($response->error_uri) ? $response->error_uri : null;
			switch($response->error) {
				case GOAuth2::ERROR_INVALID_REQUEST:
					throw new GOAuth2InvalidRequestException($error, $error_description, $error_uri);
				case GOAuth2::ERROR_INVALID_CLIENT:
					throw new GOAuth2InvalidClientException($error, $error_description, $error_uri);
				case GOAuth2::ERROR_INVALID_GRANT:
					throw new GOAuth2InvalidGrantException($error, $error_description, $error_uri);
				case GOAuth2::ERROR_UNAUTHORIZED_CLIENT:
					throw new GOAuth2UnauthorizedClientException($error, $error_description, $error_uri);
				case GOAuth2::ERROR_UNSUPPORTED_GRANT_TYPE:
					throw new GOAuth2UnsupportedGrantTypeException($error, $error_description, $error_uri);
				case GOAuth2::ERROR_INVALID_SCOPE:
					throw new GOAuth2InvalidScopeException($error, $error_description, $error_uri);
				default:
					throw new GOAuth2Exception('unknown', 'An unknown error occurred.');
			}
		}


		/**
		 * Make an HTTP request to an API endpoint, either via a GET or POST.
		 * If an access token is passed, the request is formatted to use the
		 * token's specified method of authentication - for example, if a MAC
		 * type token is passed, the Authorization header of the request will
		 * be set as needed.
		 *
		 * @param GoAuth2HttpRequest 	$request
		 * @param Bool					$use_token
		 */
		public function call(GOAuth2HttpRequest $request, $use_token = true) {

			if($use_token && !($token = $this->getActiveToken())) {
				throw new GOAuth2NoActiveTokenException('no_active_token', 'A token-based request was made, but the client has no active tokens configured.');
			}

			// If a token was specified, sign the request as appropriate.
			if($use_token) {
				switch($token->token_type) {
					case GOAuth2::TOKEN_TYPE_BEARER:
						$this->addBearerTokenToRequest($request, $token);
						break;
					case GOAuth2::TOKEN_TYPE_MAC:
						$this->addMACTokenToRequest($request, $token);
						break;
					default:
						throw new GOAuth2Exception('unknown_token', 'An unknown or malformed token was passed to GOAuth2Client::call().');
				}
			}

			return $this->sendRequest($request);
		}


		/**
		 * Sign a request using the OAuth 2.0 MAC token specification.
		 * Currently based on draft v2 of the specification.
		 *
		 * @param GOAuth2HttpRequest 	$request
		 * @param GOAuth2AccessToken	$token
		 */
		public function addMACTokenToRequest(GOAuth2HttpRequest $request, GOAuth2AccessToken $token, $hmac_algorithm = GoAuth2::HMAC_SHA1) {

			// Generate timestamp and nonce and add to params
			$timestamp 	= time();
			$nonce		= uniqid();
			$signature 	= GOAuth2::generateHMACSignature($request->uri, $token->access_token, $token->secret, $timestamp, $nonce, $request->method, $hmac_algorithm);


			// Add token, timestamp, nonce and signature to auth header
			$header_parts = array(
				'token' 	=> $token->access_token,
				'timestamp'	=> $timestamp,
				'nonce'		=> $nonce,
				'signature'	=> $signature
			);

			// Format the parameters
			$params = array();
			foreach($header_parts as $param => $value) {
				$params[] = $param . '="' . $value . '"';
			}

			// Concatenate the header parts into one
			$request->authorization_header = 'MAC ' . implode(',', $params);

			return $request;
		}

		/**
		 * Add a simple Bearer access token to the request.
		 *
		 * @param 	GOAuth2HttpRequest $request
		 * @param 	GOAuth2AccessToken $token
		 * @return	GOAuth2HttpRequest
		 */
		private function addBearerTokenToRequest(GOAuth2HttpRequest $request, GOAuth2AccessToken $token) {
			$request->authorization_header = "BEARER {$token->access_token}";
			return $request;
		}

		/**
		 * Make a HTTP request.
		 *
		 * @param	GOAuth2HttpRequest	$request
		 * @throws 	GOAuth2Exception
		 * @return	Response text.
		 */
		public function sendRequest(GOAuth2HttpRequest $request) {

			// Set the request headers
			$headers = array();

			// Add the authorization header if set
			if(!empty($request->authorization_header)) {
				$headers[] = 'Authorization: ' . $request->authorization_header;
				$request->authorization_header = null;
			}

			// Initialise the cURL handler and set transfer options.
			$ch = curl_init($request->uri);
			curl_setopt_array($ch, array(
				CURLOPT_POST 			=> ($request->method == 'POST') ? 1 : 0,
				CURLOPT_POSTFIELDS		=> $request->params,
				CURLOPT_RETURNTRANSFER 	=> 1,
				CURLOPT_HTTPHEADER		=> $headers
			));

			// Send the actual request.
			$curl_response = curl_exec($ch);

			// Check that the URI was reachable.
			if($curl_response === false) {
				$errno = curl_errno($ch);
				$error = curl_error($ch);
				curl_close($ch);
				throw new GOAuth2ConnectionException("curl_error_$errno", $error);
			}

			// Close the cURL handler.
			curl_close($ch);

			// Return the response.
			return $curl_response;
		}
	}