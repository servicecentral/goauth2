<?php

	require_once 'GOAuth2.php';

	/**
	 * OAuth2.0-compliant authorization endpoint.
	 * @package GOAuth2
	 */
	abstract class GOAuth2AuthorizationServer {

		// An array of URIs, indexed by error type, that may be provided to the client.
		private $error_uris = array();

		// Whether SSL is enforced on this authorization server.
		private $enforce_ssl;

		/**
		 * Class Constructor
		 *
		 * @param Bool $enforce_ssl		Whether to enforce SSL connections (highly
		 * 								recommended)
		 *
		 * @return AuthorizationServer
		 */
		public function __construct($enforce_ssl = true) {
			$this->enforce_ssl = $enforce_ssl;
		}


		/**
		 * Process an authorization request. This checks that all required parameters
		 * are set, and that a client and redirect URI were provided. In compliance
		 * with the OAuth2.0 spec, an invalid client or invalid redirect URI will *not*
		 * result in a redirect back to the client application, but will throw exceptions
		 * that should be caught by the calling script.
		 *
		 * Any other error - for example, a missing or invalid response type, or an invalid
		 * or unknown scope specification - will redirect the user-agent back to the client
		 * with an error message.
		 *
		 * If both $user and $user_decision are set, the function will redirect the user-agent
		 * back to the client, with either the granted code or the approprite error message.
		 *
		 * @param 	array 	$get			The $_GET variables from the authorization request.
		 * @param	mixed	$user			A means for uniquely identifying the end-user being
		 * 									served the request. This would most commonly be, for
		 * 									example, a 'user_id' stored in the $_SESSION variable.
		 * 									This value is passed on to the function which generates
		 * 									a new authorization code.
		 * @param	bool	$user_decision	Either null, true or false, representing the end-user's
		 * 									decision on whether to grant the request or not.
		 *
		 * @throws	GOAuth2InvalidClientException
		 * @throws	GOAuth2InvalidRedirectURIException
		 */
		public function processAuthorizationRequest($get, $user = null, $user_decision = null) {

			// Check SSL
			if($this->enforce_ssl) {
				if($_SERVER['HTTPS'] !== 'on') {
					throw new GOAuth2SSLException('Attempted to connect to GOAuth2 authorization server over non-HTTPS channel.');
				}
			}

			// Extract parameters from the GET request
			$params = array('response_type', 'client_id', 'redirect_uri', 'scope', 'state');
			foreach($params as $param) {
				$$param = isset($get[$param]) ? $get[$param] : null;
			}

			// Validate the client ID
			// Throw an exception rather than send a redirect, as per the OAuth2.0 spec's
			// requirement that authorization server's don't redirect in this case.
			if(!$this->validateClient($client_id)) {
				throw new GOAuth2InvalidClientException(GOAuth2::getErrorDescription(GOAuth2::ERROR_INVALID_CLIENT));
			}

			// Validate the Redirect URI
			// Throw an exception rather than send a redirect, as per the OAuth2.0 spec's
			// requirement that authorization server's don't redirect in this case.
			if(!($redirect_uri = $this->validateRedirectURI($client_id, $redirect_uri))) {
				throw new GOAuth2InvalidRedirectURIException(GOAuth2::getErrorDescription(GOAuth2::ERROR_INVALID_REDIRECT_URI));
			}

			// Client ID and Redireect URI validated, check that a response type was provided
			if(!$response_type) {
				$this->sendErrorRedirect($redirect_uri, GOAuth2::ERROR_INVALID_REQUEST, $state);
			}

			// Check that the response type is one we support (currently only 'code')
			if($response_type !== GOAuth2::RESPONSE_TYPE_CODE) {
				$this->sendErrorRedirect($redirect_uri, GOAuth2::ERROR_UNSUPPORTED_RESPONSE_TYPE, $state);
			}

			// Check that the scope requested is valid for users of the specified client
			if(!$this->validateScope($client_id, $scope)) {
				$this->sendErrorRedirect($redirect_uri, GOAuth2::ERROR_INVALID_SCOPE);
			}

			// If this request represents an end-user decision on whether to grant/deny
			// access, process it.
			if($user_decision !== null) {

				// Check to see if the user denied the request.
				if(!$user_decision) {
					$this->sendErrorRedirect($redirect_uri, GOAuth2::ERROR_ACCESS_DENIED);
				}

				// The request was approved by the end user, create a new authentication token and return to the client.
				$code = $this->generateNewAuthorizationCode($client_id, $redirect_uri, $user, $scope);
				$this->sendCodeRedirect($code, $state);
			}

		}


		/**
		 * Check that the redirect URI provided in the request is valid.
		 *
		 * @param 	String 	$client_id		The ID of the client making the request.
		 * @param 	String 	$redirect_uri	The redirect URI provided in the request, or
		 * 									null if none was provided.
		 * @return	String					The redirect URI that should be used (either
		 * 									that specified or that registered as appropriate).
		 * 									Null will be returned if no URI could be validated.
		 */
		private function validateRedirectURI($client_id, $redirect_uri) {

			// Check the client exists.
			if(!$this->validateClient($client_id)) {
				return null;
			}

			// Check that the provided redirect URI is valid.
			$registered_redirect_uri = $this->getRegisteredRedirectURIForClient($client_id);

			// If there's no registered URI, the provided URI is valid as long as it was provided.
			if(!$registered_redirect_uri) {
				return $redirect_uri;
			}

			// Otherwise, check that the provided URI matches the registered URI.
			if($registered_redirect_uri === rawurldecode($redirect_uri)) {
				return $registered_redirect_uri;
			}

			// Couldn't validate, return null.
			return null;
		}


		/**
		 * Redirect back to the client with an authorization code.
		 *
		 * @param String	$redirect_uri	The URI to redirect back to.
		 * @param String	$code			The authorization code to return.
		 * @param String	$state			Optional. The state parameter if
		 * 									specified in the original request.
		 */
		private function sendCodeRedirect(GOAuth2AuthorizationCode $code, $state = null) {
			$params = array(
				'code' => $code->code
			);

			// Append the state if defined.
			if($state) {
				$params['state'] = $state;
			}

			$this->sendRedirect($code->redirect_uri, $params);
		}


		/**
		 * Send a redirect to the specified $redirect_uri with error information.
		 *
		 * @param String $redirect_uri	The redirect URI.
		 * @param String $error			The error to send.
		 * @param String $state			Optional. The 'state' parameter if passed
		 * 								in the initial authorization request.
		 */
		private function sendErrorRedirect($redirect_uri, $error, $state = null) {
			$params = array(
				'error' 			=> $error,
				'error_description'	=> GOAuth2::getErrorDescription($error)
			);

			// Append the error URI if defined
			if(isset($this->error_uris[$error])) {
				$params['error_uri'] = $this->error_uris[$error];
			}

			// Append the state if defined
			if($state) {
				$params['state'] = $state;
			}

			$this->sendRedirect($redirect_uri, $params);
		}


		/**
		 * Redirect the current request to the given URI.
		 *
		 * @param String 	$uri	The URI to redirect to.
		 * @param array		$params	Optional. An array of parameters to add to the
		 * 							querystring of the redirect URI.
		 */
		private function sendRedirect($redirect_uri, $params = array()) {

			// Extract any existing parameters from the redirect URI.
			$uri_parts = parse_url($redirect_uri);
			parse_str($uri_parts['query'], $existing_params);
			$params = array_merge($params, $existing_params);

			// Rebuild the URI with all query parameters
			$params = http_build_query($params);
			$uri_parts = array(
				$uri_parts['scheme'] ? $uri_parts['scheme'] . '://' : '',
				$uri_parts['host'],
				$uri_parts['path'],
				empty($params) ? '' : "?$params"
			);
			$redirect_uri = implode('', $uri_parts);

			// Clean the output buffer to eliminate any whitespace.
			@ob_end_clean();

			// Set the response status code
			header(GOAuth2::HTTP_302);

			// Set the URI
			header("Location: $redirect_uri");

			// Cease processing
			exit;
		}


		/**
		 * FUNCTIONS THAT REQUIRE REIMPLEMENTATION
		 *
		 * The following functions MUST be implemented in any inheriting subclass.
		 */

		/**
		 * Check whether the specified client exists.
		 *
		 * @param 	String 	$client_id
		 * @return	Bool	True if client exists, False otherwise.
		 */
		protected function validateClient($client_id) {
			throw new Exception('GOAuth2AuthorizationServer::validateClient() not implemented.');
		}


		/**
		 * Generate a new Authorization Code for the specified client, redirect uri
		 * and scope.
		 *
		 * @param string 	$client_id		The ID of the client the authorization code is
		 * 									being generated for.
		 * @param string 	$redirect_uri	The redirect URI the authorization code is being
		 * 									sent to.
		 * @param mixed		$user			A means for uniquely identifying the end-user to
		 * 									the server implementation (eg a user ID).
		 * @param string 	$scope			The scope the authorization code should apply to.
		 *
		 * @return GOAuth2AuthorizationCode
		 */
		protected function generateNewAuthorizationCode($client_id, $redirect_uri, $user, $scope) {
			throw new Exception('GOAuth2AuthorizationServer::generateNewAuthorizationCode() not implemented.');
		}


		/**
		 * FUNCTIONS THAT REQUIRE REIMPLEMENTATION IN SOME SCENARIOS
		 *
		 * The following functions MAY need to be reimplemented in an inheriting subclass.
		 */

		/**
		 * Get any registered redirect URI for the specified client.
		 *
		 * This function MUST be reimplemented if your authorization server allows clients
		 * to preregister their redirect URIs, which is the recommended behaviour.
		 *
		 * @param 	String 	$client_id
		 * @return	String	$registered_redirect_uri	URI in decoded format if found, null otherwise.
		 */
		protected function getRegisteredRedirectURIForClient($client_id) {
			return null;
		}


		/**
		 * Validate that the specified scope is validate for the given client.
		 *
		 * This function MUST be reimplemented if you want to check the requested scope.
		 *
		 * @param 	string $client_id		The ID of the client making the request.
		 * @param 	string $scope			The space-delimited list of requested scopes given in
		 *	 								the authorization request.
		 * @return	Bool					True if requested scope is OK, false otherwise.
		 */
		protected function validateScope($client_id, $scope) {
			return true;
		}
	}