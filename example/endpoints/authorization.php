<?php

	include '../../GOAuth2AuthorizationServer.php';
	include '../lib/mongo_authorization_server.php';

	$mongo_authorization_server = new MongoAuthorizationServer();

	$mongo_authorization_server->processAuthorizationRequest($_GET);