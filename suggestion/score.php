<?php

	function isInCommentOut($file) {
		//TODO: Correspond to case there is only one vulnerability in one file.
		$contents = file_get_contents($file);
		if (strpos($contents, '<!--', strpos($contents, '<html>'))) {
			return true;
		}
		return false;
	}

	$vulnNodes = array();
	function traceChildren($nodes) {
		global $vulnNodes;
		$commentoutFlag = false;

		if (!is_array($nodes)) { return; }
		foreach($nodes as $node) {
			$commentoutFlag = isInCommentout($node->filename);

			$vuln = array(
					'marker' => $node->marker,
					'value' => $node->value
			);
			$vulnNodes[] = $vuln;

			if (isset($node->children[0])) {
				traceChildren($node->children);
			}
		}

		return $commentoutFlag;
	}

	function checkCastFunction($value) {
		foreach (TOKENS::$S_CAST_FUNCTIONS as $cast_function) {
			if (strpos($value, $cast_function) !== false) {
				return true;
			}
		}
		return false;
	}

	function checkEncloseQuotation($value) {
		$target = str_replace("&nbsp;","",$value);
		$target = html_entity_decode(strip_tags($target,'<div>'), ENT_QUOTES, 'UTF-8');

		$length = strlen($target);
		$squote = "'";
		$dquote = '"';
		$period = ".";

		$snest = $dnest = 0;
		$quoteNum = 0;
		$isQuote = false;
		$sInQuote = $dInQuote = $inVariable = $soonAfterVariable = false;

		for ($i = 0; $i < $length; $i++) {
			$str = $target[$i];
			//if ($str === ' ') { continue; }

			if (!$inVariable) {
				if ($str === $squote && !$sInQuote) {
					$sInQuote = true;
					$snest++;
				} else if ($str === $squote && $sInQuote) {
					$sInQuote = false;
					$snest--;
				} else if ($str === $dquote && !$dInQuote) {
					$dInQuote = true;
					$dnest++;
				} else if ($str === $dquote && $dInQuote) {
					$dInQuote = false;
					$dnest--;
				}

				if ($sInQuote || $dInQuote) {
					if (($str === $dquote && $sInQuote) || ($str === $squote && $dInQuote)) {
						$quoteNum++;

						if ($quoteNum > 1 && $soonAfterVariable) {
							$isQuote = true;
							return $isQuote;
						}
					}
				}
			}

			if ($str === $period && $soonAfterVariable) {
				$soonAfterVariable = false;
			}

			if ($str === $period && !$inVariable) {
				$inVariable = true;
			} else if ($str === $period && $inVariable) {
				$inVariable = false;
				$soonAfterVariable = true;
			}
		}

		return $isQuote;
	}

	function checkSetCharset() {
		$server = $_SERVER;
		if (isset($server["CONTENT_TYPE"]) && strpos($server["CONTENT_TYPE"], "charset=") !== false) {
			return true;
		}
		return false;
	}

	$frequency = array();
	$totalFrequency = 0;

	function calcFrequency($vulnBlock) {
		GLOBAL $frequency;
		GLOBAL $totalFrequency;

		global $vulnNodes;
		$vulnNodes = array();

		$castFlag = false;
		$quotationFlag = false;
		$commentOutFlag = false;
		$charSetFlag = false;
		$persistentFlag = false;

		$commentOutFlag = traceChildren($vulnBlock->treenodes);

		foreach ($vulnNodes as $node) {
			if ($node['marker'] === 2) {
				$castFlag = true;
			}
			$castCheck = checkCastFunction($node['value']);
			if ($castCheck) {
				$castFlag = true;
			}

			$quotationCheck = checkEncloseQuotation($node['value']);
			if ($quotationCheck) {
				$quotationFlag = true;
			}
		}
		$charSetFlag = checkSetCharset();

		$frequency[$castFlag][$quotationFlag][$commentOutFlag][$charSetFlag][$persistentFlag]++;
		$totalFrequency++;

		return $frequency;
	}

	function AV($value) {
		switch ($value) {
			case 0: return 0.395;
			case 1: return 0.646;
			default: return 1.0;
		}
	}

	function AC($value) {
		switch ($value) {
			case 0: return 0.35;
			case 1: return 0.61;
			default: return 0.71;
		}
	}

	function Au($value) {
		switch ($value) {
			case 0: return 0.45;
			case 1: return 0.56;
			default: return 0.704;
		}
	}

	function CIA($value) {
		switch ($value) {
			case 0: return 0.0;
			case 1: return 0.275;
			default: return 0.660;
		}
	}

	function E($value) {
		switch ($value) {
			case 0: return 0.85;
			case 1: return 0.90;
			case 2: return 0.95;
			case 3: return 1.00;
			default: return 1.00;
		}
	}

	function RL($value) {
		switch ($value) {
			case 0: return 0.87;
			case 1: return 0.90;
			case 2: return 0.95;
			case 3: return 1.00;
			default: return 1.00;
		}
	}

	function RC($value) {
		switch ($value) {
			case 0: return 0.90;
			case 1: return 0.95;
			case 2: return 1.00;
			default: return 1.00;
		}
	}

	function CD($value) {
		switch ($value) {
			case 0: return 0.0;
			case 1: return 0.1;
			case 2: return 0.3;
			case 3: return 0.4;
			case 4: return 0.5;
			default: return 0.0;
		}
	}

	function TD($value) {
		switch ($value) {
			case 0: return 0.02;
			case 1: return 0.25;
			case 2: return 0.75;
			case 3: return 1.00;
			default: return 1.00;
		}
	}

	function CR($value) {
		switch ($value) {
			case 0: return 0.5;
			case 1: return 1.0;
			case 2: return 1.51;
			default: return 0.0;
		}
	}

	function IR($value) {
		switch ($value) {
			case 0: return 0.5;
			case 1: return 1.0;
			case 2: return 1.51;
			default: return 0.0;
		}
	}

	function AR($value) {
		switch ($value) {
			case 0: return 0.5;
			case 1: return 1.0;
			case 2: return 1.51;
			default: return 0.0;
		}
	}

	$defaultRank = array(
          'AV' => 1,
          'AC' => 1,
          'Au' => 1,
          'C'  => 1,
          'I'  => 1,
          'A'  => 1,
          'E'  => 1,
          'RL' => 2,
          'RC' => 2,
          'CD' => 2,
          'TD' => 2,
          'CR' => 2,
          'IR' => 2,
          'AR' => 2
      );
	function castRank($flag) {
		global $defaultRank;
		$result = $defaultRank;
		if ($flag) {
			$result['AC'] = 2;
			$result['E'] = 0;
		}
		return $result;
	}

	function quotationRank($flag) {
		global $defaultRank;
		$result = $defaultRank;
		if ($flag) {
			$result['AC'] = 0;
			$result['E'] = 0;
		}
		return $result;
	}

	function commentOutRank($flag) {
		global $defaultRank;
		$result = $defaultRank;
		if ($flag) {
			$result['AC'] = 0;
			$result['E'] = 3;
		}
		return $result;
	}

	function charSetRank($flag) {
		global $defaultRank;
		$result = $defaultRank;
		if ($flag) {
			$result['AC'] = 2;
			$result['E'] = 3;
		}
		return $result;
	}

	function persistentRank($flag) {
		global $defaultRank;
		$result = $defaultRank;
		if ($flag) {
			$result['AC'] = 2;
			$result['E'] = 3;
		}
		return $result;
	}

	function setRank($flag) {
		$result = array();
		$castResult = castRank($flag['cast']);
		$quotationResult = quotationRank($flag['quotation']);
		$commentOutResult = commentOutRank($flag['commentOut']);
		$charSetResult = charSetRank($flag['charSet']);
		$persistentResult = persistentRank($flag['persistent']);

		$param = array('AV', 'AC', 'Au', 'C', 'I', 'A', 'E', 'RL', 'RC', 'CD', 'TD', 'CR', 'IR', 'AR');
		foreach ($param as $value) {
			$result[$value] = min($castResult[$value], $quotationResult[$value], $commentOutResult[$value], $charSetResult[$value], $persistentResult[$value]);
		}

		return $result;
	}

	$castFlag = false;
	$quotationFlag = false;
	$commentOutFlag = false;
	$charSetFlag = false;
	$persistentFlag = false;
	$C = $I = $A = $AV = $AC = $Au = $E = $RL = $RC = $CD = $TD = $CR = $IR = $AR = 0;
	function setParameter($flag) {
		GLOBAL $C, $I, $A, $AV, $AC, $Au, $E, $RL, $RC, $CD, $TD, $CR, $IR, $AR;

		$result = setRank($flag);

		$AV = AV($result['AV']);
		$AC = AC($result['AC']);
		$Au = Au($result['Au']);
		$C = CIA($result['C']);
		$I = CIA($result['I']);
		$A = CIA($result['A']);
		$E = E($result['E']);
		$RL = RL($result['RL']);
		$RC = RC($result['RC']);
		$CD = CD($result['CD']);
		$TD = TD($result['TD']);
		$CR = CR($result['CR']);
		$IR = IR($result['IR']);
		$AR = AR($result['AR']);
	}

	function calcBaseMetrics($influenceValue) {
		global $C, $I, $A, $AV, $AC, $Au;

		$influence = $influenceValue;
		if (is_null($influenceValue)) {
			$influence = 10.41 * (1 - $C) * (1 - $I) * (1 - $A);
		}

		$easiness = 20 * $AV * $AC * $Au;
		$functional = 0;
		if ($easiness != 0) {
			$functional = 1.176;
		}

		return ((0.6 * $influence) + (0.4 * $easiness) - 1.5) * $functional;
	}

	function calcTemporalMetrics($base) {
		GLOBAL $E, $RL, $RC;
		return $base * $E * $RL * $RC;
	}

	function calcEnvironmenralMetrics() {
		global $C, $I, $A, $CD, $TD, $CR, $IR, $AR;
		$adjustedInfluence = min(10.0, 10.41 * (1 - (1 - $C*$CR) * (1 - $I*$IR) * (1 - $A*$AR)));
		$adjustedBase = calcBaseMetrics($adjustedInfluence);
		$adjustedTemporal = calcTemporalMetrics($adjustedBase);

		return ($adjustedTemporal + (10 - $adjustedTemporal) * $CD) * $TD;
	}

	function calcCVSS($flag) {
		setParameter($flag);
		$base = calcBaseMetrics();
		$temporal = calcTemporalMetrics($base);
		$environmental = calcEnvironmenralMetrics();
		return $environmental;
	}

	function calcSpatialMeScore($flag) {
		GLOBAL $frequency;
		GLOBAL $totalFrequency;

		return $frequency[$flag['cast']][$flag['quotation']][$flag['commentOut']][$flag['charSet']][$flag['persistent']] * 10.0 / $totalFrequency;
	}

	function calcSpatialWorldScore($flag) {
		$result = calcCVSS($flag);
		return $result;
	}

	function calcPersistentScore($flag) {
		//TODO: How to calculate based on various XSS such as Stored XSS.
		return 0 / 10;
	}

	function calcScore($flag) {
		$totalScore = 0;
		$spatialMeRate = 1.0 / 3;
		$spatialWorldRate = 1.0 / 3;
		$persistentRate = 1 - $spatialMeRate - $spatialWorldRate;
		decho('Rate: ');decho('<br>');
		decho('SpatialMeRate: ');decho($spatialMeRate = 1.0 / 3);decho('<br>');
		decho('SpatialWorldRate: ');decho($spatialWorldRate = 1.0 / 3);decho('<br>');
		decho('TimeRate: ');decho($persistentRate = 1.0 / 3);decho('<br><br>');


		$spatialMeScore = calcSpatialMeScore($flag);
		$spatialWorldScore = calcSpatialWorldScore($flag);
		$persistentScore = calcPersistentScore($flag);

		echo('<br>');
		echo('SpatialMeScore: ');echo($spatialMeScore);echo(' , ');
		echo('SpatialWorldScore: ');echo($spatialWorldScore);echo(' , ');
		echo('TimeScore: ');echo($persistentScore);echo('<br>');

		$totalScore = $spatialMeRate * $spatialMeScore
					+ $spatialWorldRate * $spatialWorldScore
					+ $persistentRate * $persistentScore;

		decho("TotalScore: ");decho($totalScore);decho('<br><br>');
		return $totalScore;
	}

	function judgeScore($vulnBlock) {
		global $vulnNodes;
		$vulnNodes = array();

		$castFlag = false;
		$quotationFlag = false;
		$commentOutFlag = false;
		$charSetFlag = false;
		$persistentFlag = false;//Constant here.

		decho('Calculate vulnerability score.');
		$commentOutFlag = traceChildren($vulnBlock->treenodes);

		decho('Vulnerability detail : ');
		dump($vulnNodes);
		foreach ($vulnNodes as $node) {
			if ($node['marker'] === 2) {
				$castFlag = true;
			}
			$castCheck = checkCastFunction($node['value']);
			if ($castCheck) {
				$castFlag = true;
			}

			$quotationCheck = checkEncloseQuotation($node['value']);
			if ($quotationCheck) {
				$quotationFlag = true;
			}
		}
		$charSetFlag = checkSetCharset();

		$flag['cast'] = $castFlag;
		$flag['quotation'] = $quotationFlag;
		$flag['commentOut'] = $commentOutFlag;
		$flag['charSet'] = $charSetFlag;
		$flag['persistent'] = $persistentFlag;

		decho("Flag: ");
		dump($flag);

		return calcScore($flag);
	}