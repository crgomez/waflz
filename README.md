waflz 
========

Verizon Digital Media in-house implementation of ModSecurity rules engine. Waflz uses protocol buffers for its internal representation of ModSecurity rules. The rules can be expressed in one of three formats:
  * ModSecurity Rule Format
  * Protocol Buffers (Binary Format)
  * JSON

Simple ways of testing against the WAF:
  * Recreate false positives to identify the culprit
  * Recreate attack patterns to see how different configurations would have reacted to an attack
  * Test against the WAF to see where there may be gaps in protection In its current build, simply launching an attack will       include the alert in the response body

