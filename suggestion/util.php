<?php

$DEBUG = false;

function dump($value, $exit = false, $force = false) {
	if ($DEBUG || $force) {
		echo '<pre>';
		var_dump($value);
		echo '</pre>';
	}

	if ($exit) {
		exit;
	}
}

function decho($value) {
	if ($DEBUG) {
		echo $value;
	}
}