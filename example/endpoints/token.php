<?php

	include '../../GOAuth2TokenServer.php';
	include '../lib/mongo_token_server.php';

	$token_server = new MongoTokenServer();

	// Get the authorization header from the request (Apache only - other HTTP servers should reimplement)
	$headers = apache_request_headers();
	$authorization_header = isset($headers['Authorization']) ? $headers['Authorization'] : '';

	// Handle the request
	$token_server->handleTokenRequest($_POST, $authorization_header);