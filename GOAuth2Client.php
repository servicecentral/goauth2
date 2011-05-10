<?php

	require_once 'GOAuth2.php';

	/**
	 * OAuth2.0-compliant client.
	 * @package GOAuth2
	 */
	class GOAuth2Client {

		/** @var String Unique ID to identify the client to the service provider. */
		protected $client_id;

		/** @var String The private secret known only to the client and the service provider. */
		protected $client_secret;

		/** @var String The URI of the service provider's authorization endpoint. */
		protected $authorization_uri;

		/** @var String The URI to redirect the user back to after authorization. */
		protected $redirect_uri;

		/** @var String The URI of the service provider's token endpoint. */
		protected $token_uri;

		/** @var String The authentication method the token endpoint uses. */
		protected $token_auth_method;

		/** @var GOAuth2AccessToken	An access token used for requests. */
		private $token;


		/**
		 * Class constructor.
		 * @param 	String				$client_id			The client ID (aka API Key)
		 * @param 	String				$client_secret		The client secret (aka API secret)
		 * @param	String				$authorization_uri	The URI of the OAuth2.0 server's authorization endpoint.
		 * @param	String				$token_uri			The URI of the OAuth2.0 server's token endpoint.
		 * @param	String				$redirect_uri		Optional. The URI that should receive authorization grants.
		 * @param	String				$token_auth_method	Optional. The authentication method the token server uses.
		 * @param	GOAuth2AccessToken	$token				Optional. An already-obtained access token to make requests with.
		 * @return	GOAuth2Client
		 */
		public function __construct($client_id, $client_secret, $authorization_uri, $token_uri, $redirect_uri = null, $token_auth_method = GOAuth2::SERVER_AUTH_TYPE_CREDENTIALS, $token = null) {
			$this->client_id 			= $client_id;
			$this->client_secret 		= $client_secret;
			$this->authorization_uri	= $authorization_uri;
			$this->token_uri			= $token_uri;
			$this->redirect_uri			= $redirect_uri;
			$this->token_auth_method	= $token_auth_method;
			$this->token				= $token;
		}


		/**
		 * Set the token object to be used to make calls to the API endpoint.
		 * Pass NULL as the $token argument to clear the token.
		 *
		 * @param GOAuth2AccesToken $token
		 */
		public function setToken(GOAuth2AccessToken $token) {
			$this->token = $token;
		}


		/**
		 * Get the current access token being used by the client, or null if
		 * none is set.
		 *
		 * @return GOAuth2AccessToken
		 */
		public function getToken() {
			return $this->token;
		}


		/**
		 * Generate a URI for an authorization request.
		 *
		 * @param 	String $scope		Optional. A space-delimited list of requested scopes.
		 * @param 	String $state		Optional. A value that can be used to maintain state
		 * 								between the authorization request and the callback.
		 * @return	String				A URI.
		 */
		public function getAuthorizationRequestURI($scope = null, $state = null) {

			// Get any query parameters already in the authorization URI
			$uri_parts 		= parse_url($this->authorization_uri);
			parse_str($uri_parts['query'], $params);

			// Configure required parameters
			$params['response_type'] 	= GOAuth2::RESPONSE_TYPE_CODE;
			$params['client_id'] 		= $this->client_id;

			// Add optional parameters
			if($this->redirect_uri) { $params['redirect_uri'] = $this->redirect_uri; }
			if($scope) 				{ $params['scope'] = $scope; }
			if($state) 				{ $params['state'] = $state; }

			// Construct and return the URI
			$params = http_build_query($params);
			$uri_parts = array(
				$uri_parts['scheme'] ? $uri_parts['scheme'] . '://' : '',
				$uri_parts['host'],
				$uri_parts['path'],
				empty($params) ? '' : "?$params"
			);
			return implode('', $uri_parts);
		}


		/**
		 * Get a token using the credentials of the resource owner directly.
		 *
		 * Note that any API calls made after this function has successfully
		 * returned a token will *not* automatically use the returned token -
		 * you should call setToken() to do this.
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
		 * Note that any API calls made after this function has successfully
		 * returned a token will *not* automatically use the returned token -
		 * you should call setToken() to do this.
		 *
		 * @param	String	$scope	Optional. A space-delimited list describing the
		 * 							scope of the token request.
		 * @return	GOAuth2AccessToken
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
		 * Get a token using a previously obtained authorization code.
		 *
		 * Note that any API calls made after this function has successfully
		 * returned a token will *not* automatically use the returned token -
		 * you should call setToken() to do this.
		 *
		 * @param 	String 	$authorization_code
		 * @return	GOAuth2AccessToken
		 */
		public function getTokenByAuthorizationCode(GOAuth2AuthorizationCode $code) {

			// Set parameters required for the token request.
			$params = array(
				'grant_type'	=> GOAuth2::GRANT_TYPE_CODE,
				'code'			=> $code->code,
				'redirect_uri'	=> $code->redirect_uri
			);

			// Construct the token request.
			$token_request = new GOAuth2HttpRequest($this->token_uri, 'POST', $params);

			// Make the token request.
			return $this->makeTokenRequest($token_request);
		}


		/**
		 * Refresh a held access token.
		 *
		 * Note that any API calls made after this function has successfully
		 * returned a token will *not* automatically use the returned token -
		 * you should call setToken() to do this.
		 *
		 * @param GOAuth2AccessToken	$token	The held token.
		 * @param String				$scope	Optional. A space-delimited list describing
		 * 										the scope of the token request.
		 *
		 * @return	GOAuth2AccessToken
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
				case GOAuth2::SERVER_AUTH_TYPE_CREDENTIALS:
					// Client credentials (the default authentication method).
					// Add the client ID and client secret to the request.
					$request->params['client_id'] 		= $this->client_id;
					$request->params['client_secret'] 	= $this->client_secret;
					break;

				case GOAuth2::SERVER_AUTH_TYPE_HTTP_BASIC:
					// HTTP BASIC authentication (not really recommended).
					// Add the BASIC auth details to the Auth header.
					$authorization_string			= base64_encode("{$this->client_id}:{$this->client_secret}");
					$request->authorization_header 	= "Authorization: Basic $authorization_string";
					break;

				case GOAuth2::SERVER_AUTH_TYPE_ANONYMOUS:
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
		 * @param GOAuth2HttpRequest 	$request
		 * @param Bool					$use_token
		 */
		public function call(GOAuth2HttpRequest $request, $use_token = true) {

			if($use_token && !($token = $this->token)) {
				throw new GOAuth2NoTokenException('no_token', 'A token-based request was made, but the client has no token configured.');
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
		public function addMACTokenToRequest(GOAuth2HttpRequest $request, GOAuth2AccessToken $token, $hmac_algorithm = GOAuth2::HMAC_SHA1) {

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