#!/bin/bash

cat radius-orig.cfg | sed "s/Secret.*$/Secret\tXXYYXX/" |\
  sed "s/Host.*$/Host\tXXYYXX/" |\
  sed "s/AuthDN.*$/AuthDN\tXXYYXX/" |\
  sed "s/AuthPassword.*$/AuthPassword\tXXYYXX/" |\
  sed "s/BaseDN.*$/BaseDN\tXXYYXX/" |\
  sed "s/PasswordAttr.*$/PasswordAttr\tXXYYXX/" |\
  sed "s/CATrustTestPswd\s.*$/CATrustTestPswd\tXXYYXX/" |\
  sed "s/CATrustTestUser\s.*$/CATrustTestUser\tXXYYXX/" > radius.cfg