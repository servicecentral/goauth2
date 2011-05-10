<?php

	require_once 'GOAuth2.php';

	/**
	 * OAuth2.0-compliant token endpoint.
	 * @package GOAuth2
	 */
	abstract class GOAuth2TokenServer {

		// The type of token the token server hands out.
		protected $token_type;

		// The method the token server uses to authenticate clients.
		protected $client_auth_method;

		// The algorithm used to generate HMAC signature.
		protected $hmac_algorithm;

		// An array of URIs, indexed by error type, that may be provided to the client.
		protected $error_uris 		= array();

		public function __construct($token_type = GoAuth2::TOKEN_TYPE_MAC, $client_auth_method = GoAuth2::SERVER_AUTH_TYPE_CREDENTIALS, $hmac_algorithm = GOAuth2::HMAC_SHA1) {
			$this->token_type			= $token_type;
			$this->client_auth_method 	= $client_auth_method;
			$this->hmac_algorithm		= $hmac_algorithm;
		}

		/**
		 * Handle a request for a token to the token endpoint.
		 *
		 * @param array		$post					The POST fields of the request.
		 * @param String 	$authorization_header	The Authorization header field.
		 */
		public function handleTokenRequest($post, $authorization_header) {

			// Check for required parameters.
			if(!isset($post['grant_type'])) {
				$this->sendErrorResponse(GOAuth2::ERROR_INVALID_REQUEST);
			}

			// Handle the token request depending on its type.
			switch($post['grant_type']) {
				case GOAuth2::GRANT_TYPE_CODE:
					$this->handleTokenRequestWithAuthorizationCode($post, $authorization_header);
					break;
				case GOAuth2::GRANT_TYPE_CLIENT_CREDENTIALS:
					$this->handleTokenRequestWithClientCredentials($post, $authorization_header);
					break;
				case GOAuth2::GRANT_TYPE_PASSWORD:
					$this->handleTokenRequestWithPassword($post, $authorization_header);
					break;
				case GoAuth2::GRANT_TYPE_REFRESH_TOKEN:
					$this->handleTokenRefreshRequest($post, $authorization_header);
					break;
				default:
					$this->sendErrorResponse(GOAuth2::ERROR_INVALID_REQUEST);
			}

		}


		/**
		 * Handle a request for an access token using a previously obtained
		 * authorization code. This is the flow used when a client would like
		 * to obtain access on behalf of an end-user.
		 *
		 * @param array		$post					The POST array given with the request.
		 * @param String	$authorization_header	The contents of the Authorization: header.
		 */
		private function handleTokenRequestWithAuthorizationCode($post, $authorization_header) {

			// Get the authorization code and redirect URI from the POST
			$client_id 		= isset($post['client_id']) ? $post['client_id'] : null;
			$client_secret 	= isset($post['client_secret']) ? $post['client_secret'] : null;
			$code 			= isset($post['code']) ? $post['code'] : null;
			$redirect_uri 	= isset($post['redirect_uri']) ? $post['redirect_uri'] : null;

			// Authenticate the client request
			$this->authenticateClientRequest($client_id, $client_secret, $authorization_header);

			// Check that a code and redirect_uri was passed
			if(empty($code) || empty($redirect_uri)) {
				$this->sendErrorResponse(GoAuth2::ERROR_INVALID_REQUEST);
			}

			// Validate the authorization code information
			// @todo: There are issues here if not using the credentials means of authorization.
			$this->validateAuthorizationCode($client_id, $code, $redirect_uri);

			$token = $this->generateAccessToken($client_id);

		}


		/**
		 * Handle a request for an access token using just the client credentials.
		 * This flow is used when the client would like to obtain access on behalf
		 * of itself.
		 *
		 * @param array		$post					The POST array given with the request.
		 * @param String	$authorization_header	The contents of the Authorization: header.
		 */
		private function handleTokenRequestWithClientCredentials($post, $authorization_header) {

			// Get the client_id, client_secret and scope parameters from the POST if present.
			$client_id 		= isset($post['client_id']) ? $post['client_id'] : null;
			$client_secret 	= isset($post['client_secret']) ? $post['client_secret'] : null;
			$scope			= isset($post['scope']) ? $post['scope'] : null;

			// Authenticate the client request
			$this->authenticateClientRequest($client_id, $client_secret, $authorization_header);

			// Check that the scope requested is permissible
			$this->checkTokenRequestScope($client_id, $for_user = null, $scope);

			// Get a new access token
			$token = $this->generateAccessToken($client_id, $for_user = null, $scope);

			// Send the generated token back to the client
			$this->sendResponse(GOAuth2::HTTP_200, $token->toJSON(), GOAuth2::CONTENT_TYPE_JSON, $no_store = true);
		}


		/**
		 * Handle a request to obtain an access token with the resource owner username
		 * and password.
		 *
		 * @param array 	$post					The POST array of the request.
		 * @param String 	$authorization_header	The contents of the Authorization header.
		 */
		private function handleTokenRequestWithPassword($post, $authorization_header) {

			// Get the client_id, client_secret, username, password and scope parameters from the POST if present.
			$client_id 		= isset($post['client_id']) ? $post['client_id'] : null;
			$client_secret 	= isset($post['client_secret']) ? $post['client_secret'] : null;
			$username 		= isset($post['username']) ? $post['username'] : null;
			$password 		= isset($post['password']) ? $post['password'] : null;
			$scope			= isset($post['scope']) ? $post['scope'] : null;

			// Authenticate the client request
			$this->authenticateClientRequest($client_id, $client_secret, $authorization_header);

			// Check that a username and password was passed
			if(empty($username) || empty($password)) {
				$this->sendErrorResponse(GoAuth2::ERROR_INVALID_REQUEST);
			}

			// Validate the resource owner credentials
			$this->validateResourceOwnerCredentials($username, $password);

			// Check that the scope requested is permissible
			$this->checkTokenRequestScope($client_id, $username, $scope);

			// Get a new token
			$token = $this->generateAccessToken($client_id, $username, $scope);

			$this->sendResponse(GOAuth2::HTTP_200, $token->toJSON(), GOAuth2::CONTENT_TYPE_JSON, $no_store = true);
		}


		/**
		 * Handle a request to refresh an access token with the given refresh token.
		 *
		 * @param array 	$post					The POST array of the request.
		 * @param String	$authorization_header	The contents of the Authorization header.
		 */
		private function handleTokenRefreshRequest($post, $authorization_header) {

			// Get the client_id, client_secret, refresh token and scope parameters from the POST if present.
			$client_id 		= isset($post['client_id']) ? $post['client_id'] : null;
			$client_secret 	= isset($post['client_secret']) ? $post['client_secret'] : null;
			$refresh_token 	= isset($post['refresh_token']) ? $post['refresh_token'] : null;
			$scope			= isset($post['scope']) ? $post['scope'] : null;

			// Authenticate the client request
			$this->authenticateClientRequest($client_id, $client_secret, $scope, $authorization_header);

			// Check that a refresh token was passed
			if(empty($refresh_token)) {
				$this->sendErrorResponse(GoAuth2::ERROR_INVALID_REQUEST);
			}

			// Refresh the access token
			$token = $this->refreshAccessToken($client_id, $refresh_token, $scope);

			// Send the generated token back to the client
			$this->sendResponse(GOAuth2::HTTP_200, $token->toJSON(), GOAuth2::CONTENT_TYPE_JSON, $no_store = true);
		}


		/**
		 * Authenticate a request from a client using the authentication method
		 * specified by the server.  This will most often be using the method
		 * specified in s3.1 of the OAuth specification, namely the presence of
		 * a client_id and client_secret POST field.
		 *
		 * However, as noted in the specification, other authentication methods
		 * (such as HTTP BASIC) or anonymous access may be permitted.
		 *
		 * @param String 	$client_id
		 * @param String 	$client_secret
		 * @param String	$authorization_header
		 */
		private function authenticateClientRequest($client_id, $client_secret, $authorization_header) {

			switch($this->client_auth_method) {
				case GOAuth2::SERVER_AUTH_TYPE_ANONYMOUS:
					// Anonymous access is permitted.
					return;

				case GOAuth2::SERVER_AUTH_TYPE_HTTP_BASIC:

					// Extracted the base64-encoded string from the header.
					if(!preg_match('/^Authorization:\s+Basic\s+(\w+==)$/', $authorization_header, $matches)) {
						$this->sendErrorResponse(GoAuth2::ERROR_INVALID_CLIENT);
					}

					// Decode the authorization information and check that it's in u:p form
					try {
						list($_, $authorization_string) = $matches;
						list($username, $password) = explode(':', base64_decode($authorization_string));
					} catch(Exception $e) {
						$this->sendErrorResponse(GoAuth2::ERROR_INVALID_CLIENT);
					}

					// Authenticate the HTTP BASIC credentials.
					// NB: Currently we assume that the credentials being passed in the BASIC header
					// are the client_id and client_secret.
					// @todo: Generalise this.
					$this->authenticateClientCredentials($username, $password);

					// Authentication was successful.
					return;

				case GOAuth2::SERVER_AUTH_TYPE_CREDENTIALS:
					// Using the (default) credentials method.

					// Check for client_id and client_secret, required for request.
					if(empty($client_id) || empty($client_secret)) {
						$this->sendErrorResponse(GOAuth2::ERROR_INVALID_CLIENT);
					}

					// Authenticate the client id and client secret
					$this->authenticateClientCredentials($client_id, $client_secret);

					// Authentication was successful.
					return;

				default:
					// Unknown authentication method.
					throw new Exception('Unknown server authentication method specified.');
					return;
			}
		}


		/**
		 * Send an error response from the server as specified by the OAuth 2.0
		 * specification.  This requires a JSON response with an "error" field
		 * and optional description and URI fields.
		 *
		 * @param String	$error	A string representing one of the error types
		 * 							specified in s5.2 of the OAuth 2.0 spec, eg
		 * 							'invalid_request' or 'invalid_scope'.
		 */
		protected function sendErrorResponse($error = GoAuth2::ERROR_INVALID_REQUEST) {
			// Create the JSON response object
			$error_object = array(
				'error' 			=> $error,
				'error_description'	=> GOAuth2::getErrorDescription($error)
			);

			// Append the error URI if defined
			if(isset($this->error_uris[$error])) {
				$error_object['error_uri'] = $this->error_uris[$error];
			}

			// Encode the error into JSON
			$error_json = json_encode($error_object);

			// Get the appropriate HTTP response code for this type of error
			$http_response_code = GOAuth2::getErrorHttpStatusCode($error);

			// Send the HTTP response
			$this->sendResponse($http_response_code, $error_json);
		}


		/**
		 * Send an HTTP response to the client.
		 *
		 * @param 	int 	$status			The HTTP response status code to send.
		 * @param	String	$response		The body of the response.
		 * @param	String	$content_type	Optional .The content type of the response.
		 * 									Defaults to 'application/json'.
		 */
		private function sendResponse($status, $response, $content_type = GOAuth2::CONTENT_TYPE_JSON, $no_store = false) {
			// Clean the output buffer to eliminate any whitespace.
			@ob_end_clean();

			// Set the response status code
			header($status);

			// Set the content type of the response
			header("Content-Type: $content_type");

			// Set the Cache-Control: no-store header if desired
			if($no_store) {
				header("Cache-Control: no-store");
			}

			// Send the response text
			echo $response;

			// Cease processing
			exit;
		}


		/**
		 * FUNCTIONS WHICH REQUIRE REIMPLEMENTATION
		 *
		 * The following functions MUST be implemented in any inheriting subclass.
		 */

		/**
		 * Check that the specified client is permitted to obtain an access token
		 * of the specified scope for the specified user.  Both the user and scope
		 * parameters are optional, as a client may request a token for themselves
		 * (not on behalf of a user) and the 'scope' parameter is an optional
		 * request parameter.  There may be only one default scope or your server
		 * implementation may treat a lack of scope specificity as a request for
		 * the maximum permitted scope.
		 *
		 * This function MUST be reimplemented in the inheriting subclass.
		 *
		 * @param String	$client_id	The ID of the client who is requesting the token.
		 * @param String	$for_user	Optional. If given, represents the username of the
		 * 								resource owner on whose behalf the token is being
		 * 								requested.
		 * @param String	$scope		Optional. If given, is a space-delimited string of
		 * 								requested scopes.
		 */
		protected function checkTokenRequestScope($client_id, $for_user = null, $scope = null) {
			throw new Exception('checkTokenRequestScope() not implemented by server.');
		}

		/**
		 * Generate and store an access token for the given client with
		 * the given scope.
		 *
		 * This function MUST be reimplemented in the inheriting subclass.
		 *
		 * @param	String	$client_id	The ID of the client to be given
		 * 								the token.
		 * @param	String	$for_user	Optional. If given, represents
		 * 								the username of the resource
		 * 								owner on whose behalf the token
		 * 								is being generated.
		 * @param	String	$scope		Optional. If given, a string of
		 * 								space-delimited scope names.
		 */
		protected function generateAccessToken($client_id, $for_user = null, $scope = null) {
			throw new Exception('generateAccessToken() not implemented by server.');
		}

		/**
		 * Refresh and store an access token for the given client with
		 * the given scope.
		 *
		 * This function MUST be reimplemented in the inheriting subclass.
		 *
		 * @param	String	$client_id		The ID of the client to be given
		 * 									the token.
		 * @param	String	$refresh_token	The refresh token provided by
		 * 									the client.
		 * @param	String	$scope			Optional. If given, a string of
		 * 									space-delimited scope names.
		 */
		protected function refreshAccessToken($client_id, $refresh_token, $scope = null) {
			throw new Exception('refreshAccessToken() not implemented by server.');
		}


		/**
		 * FUNCTIONS THAT MUST BE REIMPLEMENTED IN SOME SCENARIOS
		 *
		 * The following functions MUST be reimplemented in any inheriting subclass
		 * IF the inheriting Token Server needs to support the relevant feature.
		 */

		/**
		 * Generate and store an access token from the given authorization
		 * code. This function must only be called after the code has been
		 * validated.
		 *
		 * This function MUST be reimplemented if the server utilises the
		 * authorization code flow.
		 *
		 * @param 	String $code	The authorization code.
		 * @return	GOAuth2AccessToken
		 */
		protected function generateAccessTokenFromAuthorizationCode($code) {
			throw new Exception('generateAccessTokenFromAuthorizationCode() not implemented by server.');
		}

		/**
		 * Authenticate the given client credentials.  This function must be
		 * reimplemented in the inheriting server subclass if that server
		 * utilises the client credentials authentication method. The function
		 * implementation MUST call the sendErrorResponse() method on a failed
		 * authentication.
		 *
		 * @param String	$client_id
		 * @param String	$client_secret
		 */
		protected function authenticateClientCredentials($client_id, $client_secret) {
			throw new Exception('authenticateClientCredentials() not implemented by server.');
		}

		/**
		 * Validate the given resource owner credentials. This function must be
		 * reimplemented in the inheriting subclass if the server needs to
		 * support the resource owner credentials flow of access token grant.
		 *
		 * The OAuth specification notes that this flow should only be used
		 * where there is a high level of trust between the resource owner
		 * and the client, and should only be used where other flows aren't
		 * available. It is also used when migrating a client from a
		 * stored-password approach to an access token approach.
		 *
		 * @param	String	$client_id		The ID of the client to be given
		 * 									the token.
		 * @param	String	$refresh_token	The refresh token provided by
		 * 									the client.
		 * @param	String	$scope			Optional. If given, a string of
		 * 									space-delimited scope names.
		 */
		protected function validateResourceOwnerCredentials($username, $password) {
			throw new Exception('validateResourceOwnerCredentials() not implemented by server.');
		}

		/**
		 * Validate the given authorization code details. This function must
		 * be reimplemented in the inheriting subclass if the server needs to
		 * support the authorization code flow of access token grant.
		 *
		 * @param	String	$client_id		The ID of the client requesting the
		 * 									token. This MUST be checked against
		 * 									the ID of the client that was given
		 * 									the authorization code by the
		 * 									authorization server.
		 * @param	String	$code			The authorization code.
		 * @param	String	$redirect_uri	The redirect URI the client claims it
		 * 									obtained during the authorization
		 * 									process. This MUST be checked against
		 * 									the redirect URI logged by the
		 * 									authorization server.
		 */
		protected function validateAuthorizationCode($client_id, $code, $redirect_uri) {
			throw new Exception('validateAuthorizationCode() not implemented by server.');
		}
	}