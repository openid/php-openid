<?php

class OpenID_KVForm {
	function arrayToKV($values) {
		$serialized = '';
		foreach ($values as $key => $value) {
			if (
				strpos($key, ':') !== FALSE ||
				strpos($key, "\n") !== FALSE ||
				strpos($value, "\n") !== FALSE
				) {
				return NULL;
			}

			$serialized .= "$key:$value\n";
		}
		return $serialized;
	}

	function kvToArray($kvs) {
		$lines = explode("\n", $kvs);

		$last = array_pop($lines);
		if ($last !== '') {
			// Log error (no newline at end)
			array_push($lines, $last);
		}

		$values = array();

		foreach ($lines as $line) {
			$kv = explode(':', $line, 2);
			if (count($kv) != 2) {
				// Log error (no colon on line)
				continue;
			}

			$key = $kv[0];
			$tkey = trim($key);
			if ($tkey != $key) {
				// Log error (whitespace on key)
			}

			$value = $kv[1];
			$tval = trim($value);
			if ($tval != $value) {
				// Log error (whitespace on value)
			}

			$values[$tkey] = $tval;
		}
		
		return $values;
	}
}

?>