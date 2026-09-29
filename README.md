# Observation-Wazuh

Des notes sur les règles Wazuh avec l'utilisation de Nuclei, le but était de voir les détections sur des scans de Nuclei, et de faire du mapping MITRE


## Ruleset Wazuh

les regles Web sont les fichiers 0245-web_rules.xml et 0270-web_appsec_rules.xml dans `/var/ossec/ruleset/rules`, des modifications

# Modifications de règles

Notamment la règles Common Web Attack

```
  <rule id="31104" level="6">
    <if_sid>31100</if_sid>

    <!-- Attempt to do directory transversal, simple sql injections,
      -  or access to the etc or bin directory (unix). -->
    <url>%027|%00|%01|%7f|%2E%2E|%0A|%0D|../..|..\..|echo;|</url>
    <url>cmd.exe|root.exe|_mem_bin|msadc|/winnt/|/boot.ini|</url>
    <url>/x90/|default.ida|/sumthin|nsiislog.dll|chmod%|wget%|cd%20|</url>
    <url>exec%20|../..//|%5C../%5C|././././|2e%2e%5c%2e|\x5C\x5C</url>
    <description>Common web attack.</description>
    <mitre>
      <id>T1055</id>
      <id>T1083</id>
      <id>T1190</id>
    </mitre>
    <group>attack,pci_dss_6.5,pci_dss_11.4,pci_dss_6.5.1,gdpr_IV_35.7.d,nist_800_53_SA.11,nist_800_53_SI.4,tsc_CC6.6,tsc_CC7.1,tsc_CC8.1,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>
```


On peut ajouter la détections de 

```
..%2f.
..%5c..
%c0%ae/
win.ini et .%2e/
```

## Worpress


IOn peut ajouter des règles pour détecter le scan de theme et de plugin Wordpress


### Test Nuclei

```
nuclei -u http://192.168.57.2/ -include-templates http/fuzzing/ -t http/fuzzing/wordpress-themes-detect.yaml
nuclei -u http://192.168.57.2/ -include-templates http/fuzzing/ -t http/fuzzing/wordpress-plugins-detect.yaml
```

```
  <rule id="100002" level="6">
    <if_sid>31100,31108,31101</if_sid>
    <url type="osregex">/wp-content/plugins/(\w*)/readme.txt</url>
    <description>Worpress plugin discover</description>
    <mitre>
      <id>T1595</id>
      <id>T1595.003</id>
      <id>T1190</id>
    </mitre>
    <group>attack,pci_dss_6.5,pci_dss_11.4,pci_dss_6.5.1,gdpr_IV_35.7.d,nist_800_53_SA.11,nist_800_53_SI.4,tsc_CC6.6,tsc_CC7.1,tsc_CC8.1,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>


  <rule id="100003" level="6">
    <if_sid>31100,31108,31101</if_sid>
    <url type="osregex">/wp-content/themes/(\w+)/readme.txt</url>
    <description>Worpress themes discover</description>
    <mitre>
      <id>T1595</id>
      <id>T1595.003</id>
      <id>T1190</id>
    </mitre>
    <group>attack,pci_dss_6.5,pci_dss_11.4,pci_dss_6.5.1,gdpr_IV_35.7.d,nist_800_53_SA.11,nist_800_53_SI.4,tsc_CC6.6,tsc_CC7.1,tsc_CC8.1,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>
```


Puis les sous règles pour détecter les 200 et les scans

```
  <rule id="100004" level="7">
    <if_sid>100002</if_sid>
    <id>^200</id>
    <description>Misconfig (plugin accessible)</description>
    <mitre>
      <id>T1595</id>
      <id>T1595.003</id>
      <id>T1190</id>
    </mitre>
    <group>attack,pci_dss_6.5,pci_dss_11.4,pci_dss_6.5.1,gdpr_IV_35.7.d,nist_800_53_SA.11,nist_800_53_SI.4,tsc_CC6.6,tsc_CC7.1,tsc_CC8.1,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>


  <rule id="100005" level="7">
    <if_sid>100003</if_sid>
    <id>^200</id>
    <description>Misconfig (themes accessible)</description>
    <mitre>
      <id>T1595</id>
      <id>T1595.003</id>
      <id>T1190</id>
    </mitre>
    <group>attack,pci_dss_6.5,pci_dss_11.4,pci_dss_6.5.1,gdpr_IV_35.7.d,nist_800_53_SA.11,nist_800_53_SI.4,tsc_CC6.6,tsc_CC7.1,tsc_CC8.1,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>
```


```
  <rule id="100006" level="10" frequency="10" timeframe="60">
    <if_matched_sid>100002</if_matched_sid>
    <same_source_ip />
    <description>Scan de plugin wordpress</description>
    <mitre>
      <id>T1595</id>
      <id>T1595.003</id>
      <id>T1190</id>
    </mitre>
    <group>attack,pci_dss_6.5,pci_dss_11.4,pci_dss_6.5.1,gdpr_IV_35.7.d,nist_800_53_SA.11,nist_800_53_SI.4,tsc_CC6.6,tsc_CC7.1,tsc_CC8.1,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>


  <rule id="100007" level="10" frequency="10" timeframe="60">
    <if_matched_sid>100003</if_matched_sid>
    <same_source_ip />
    <description>Scan de themes wordpress</description>
    <mitre>
      <id>T1595</id>
      <id>T1595.003</id>
      <id>T1190</id>
    </mitre>
    <group>attack,pci_dss_6.5,pci_dss_11.4,pci_dss_6.5.1,gdpr_IV_35.7.d,nist_800_53_SA.11,nist_800_53_SI.4,tsc_CC6.6,tsc_CC7.1,tsc_CC8.1,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>
```

## openRedirect

```
  <rule id="100017" level="6">
    <if_sid>31100,31108,31101</if_sid>
    <url>=http://|=https://|=http%3A%2F%2|=https%3A%2F%2|=http:%2F%2|=https:%2F%2</url>
    <description>Vulnerabilité openRedirect possible ?</description>
    <mitre>
      <id>T1595</id>
      <id>T1595.003</id>
      <id>T1190</id>
    </mitre>
    <group>attack,pci_dss_6.5,pci_dss_11.4,pci_dss_6.5.1,gdpr_IV_35.7.d,nist_800_53_SA.11,nist_800_53_SI.4,tsc_CC6.6,tsc_CC7.1,tsc_CC8.1,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>

  <rule id="100018" level="7">
    <if_sid>100017</if_sid>
    <id>^200</id>
    <description>openRedirect en succès</description>
    <mitre>
      <id>T1595</id>
      <id>T1595.003</id>
      <id>T1190</id>
    </mitre>
    <group>attack,pci_dss_6.5,pci_dss_11.4,pci_dss_6.5.1,gdpr_IV_35.7.d,nist_800_53_SA.11,nist_800_53_SI.4,tsc_CC6.6,tsc_CC7.1,tsc_CC8.1,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>
  <rule id="100019" level="10" frequency="10" timeframe="60">
    <if_matched_sid>100017</if_matched_sid>
    <same_source_ip />
    <description>Scan openredirect</description>
    <mitre>
      <id>T1595</id>
      <id>T1595.003</id>
      <id>T1190</id>
    </mitre>
    <group>attack,pci_dss_6.5,pci_dss_11.4,pci_dss_6.5.1,gdpr_IV_35.7.d,nist_800_53_SA.11,nist_800_53_SI.4,tsc_CC6.6,tsc_CC7.1,tsc_CC8.1,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>
```


les Technique MITRE

Initial Access (TA0001)	Phishing (T1566) (T1566.001)

le scan

```
nuclei -u http://192.168.57.2/ -t http/cves/2004/CVE-2004-1965.yaml
```

## Backup exposure


Chercher les extensions liées au backup

```
php.disabled,php.backup,.sql,.bak.sdb,.sqlite,.sqlitedb
```

Scan

```
nuclei -u http://192.168.57.2/ -include-templates http/exposures/ -t http/exposures/backups
```
```
<rule id="100023" level="6">
    <if_sid>31100,31108,31101</if_sid>
    <url>.sql|.bak|.sdb|.sqlite|.sqlitedb|.php.disabled|.php.backup</url>
    <description>Accès a un dump SQL/PHP backup exposé ?</description>
    <mitre>
      <id>T1595</id>
      <id>T1595.003</id>
      <id>T1190</id>
    </mitre>
    <group>attack,pci_dss_6.5,pci_dss_11.4,pci_dss_6.5.1,gdpr_IV_35.7.d,nist_800_53_SA.11,nist_800_53_SI.4,tsc_CC6.6,tsc_CC7.1,tsc_CC8.1,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3</group>
  </rule>

  <rule id="100024" level="7">
    <if_sid>100023</if_sid>
    <id>^200</id>
    <description>Accès a un dump SQL/PHP backup exposé (Possible fuite de données)</description>
    <mitre>
      <id>T1595</id>
      <id>T1595.003</id>
      <id>T1190</id>
    </mitre>
    <group>attack,pci_dss_6.5,pci_dss_11.4,pci_dss_6.5.1,gdpr_IV_35.7.d,nist_800_53_SA.11,nist_800_53_SI.4,tsc_CC6.6,tsc_CC7.1,tsc_CC8.1,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3</group>
  </rule>

  <rule id="100025" level="10" frequency="10" timeframe="60">
    <description>Scan de backup</description>
    <if_matched_sid>100023</if_matched_sid>
    <same_source_ip />
    <mitre>
      <id>T1595</id>
      <id>T1595.003</id>
      <id>T1190</id>
    </mitre>
    <group>attack,pci_dss_6.5,pci_dss_11.4,pci_dss_6.5.1,gdpr_IV_35.7.d,nist_800_53_SA.11,nist_800_53_SI.4,tsc_CC6.6,tsc_CC7.1,tsc_CC8.1,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3</group>
  </rule>
```

## Exposure symfony

```
nuclei -u http://192.168.57.2/ -include-templates http/misconfiguration/ -t http/misconfiguration/symfony/symfony-fragment.yaml -trace-log trace.log
```

```
  <rule id="100020" level="6">
    <if_sid>31100,31108,31101</if_sid>
    <url>admin_dev.php|index_dev.php|app_dev.php|</url>
    <description>symfony-debug</description>
    <mitre>
      <id>T1595</id>
      <id>T1595.003</id>
      <id>T1190</id>
    </mitre>
    <group>attack,pci_dss_6.5,pci_dss_11.4,pci_dss_6.5.1,gdpr_IV_35.7.d,nist_800_53_SA.11,nist_800_53_SI.4,tsc_CC6.6,tsc_CC7.1,tsc_CC8.1,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3</group>
  </rule>
  <rule id="100021" level="7">
    <if_sid>100020</if_sid>
    <id>^200</id>
    <description>symfony-debug</description>
    <mitre>
      <id>T1595</id>
      <id>T1595.003</id>
      <id>T1190</id>
    </mitre>
    <group>attack,pci_dss_6.5,pci_dss_11.4,pci_dss_6.5.1,gdpr_IV_35.7.d,nist_800_53_SA.11,nist_800_53_SI.4,tsc_CC6.6,tsc_CC7.1,tsc_CC8.1,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3</group>
  </rule>
  <rule id="100022" level="10" frequency="10" timeframe="60">
    <description>symfony-debug</description>
    <if_matched_sid>100020</if_matched_sid>
    <same_source_ip />
    <mitre>
      <id>T1595</id>
      <id>T1595.003</id>
      <id>T1190</id>
    </mitre>
    <group>attack,pci_dss_6.5,pci_dss_11.4,pci_dss_6.5.1,gdpr_IV_35.7.d,nist_800_53_SA.11,nist_800_53_SI.4,tsc_CC6.6,tsc_CC7.1,tsc_CC8.1,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3</group>
  </rule>
```

## Tomcat Admin

```
nuclei -u http://192.168.57.2/ -include-templates http/exposed-panels -t http/exposed-panels/apache/apache-tomcat-exposed.yaml
```


```
  <rule id="1000011" level="6">
    <if_sid>31100,31108,31101</if_sid>
    <url>/host-manager/html|/manager/status|/manager/html|/docs/RELEASE-NOTES.txt|</url>
    <description>Decouverte Tomcat manager</description>
    <mitre>
      <id>T1595</id>
      <id>T1595.003</id>
      <id>T1190</id>
    </mitre>
    <group>attack,pci_dss_6.5,pci_dss_11.4,pci_dss_6.5.1,gdpr_IV_35.7.d,nist_800_53_SA.11,nist_800_53_SI.4,tsc_CC6.6,tsc_CC7.1,tsc_CC8.1,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>
```



```
  <rule id="1000012" level="7">
    <if_sid>100011</if_sid>
    <id>^200</id>
    <description>Accès Tomcat decouverte</description>
    <mitre>
      <id>T1595</id>
      <id>T1595.003</id>
      <id>T1190</id>
    </mitre>
    <group>attack,pci_dss_6.5,pci_dss_11.4,pci_dss_6.5.1,gdpr_IV_35.7.d,nist_800_53_SA.11,nist_800_53_SI.4,tsc_CC6.6,tsc_CC7.1,tsc_CC8.1,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>


  <rule id="1000013" level="10" frequency="4" timeframe="30">
    <if_matched_sid>1000011</if_matched_sid>
    <description>Scan de manager Tomcat</description>
    <mitre>
      <id>T1595</id>
      <id>T1595.003</id>
      <id>T1190</id>
    </mitre>
    <group>attack,pci_dss_6.5,pci_dss_11.4,pci_dss_6.5.1,gdpr_IV_35.7.d,nist_800_53_SA.11,nist_800_53_SI.4,tsc_CC6.6,tsc_CC7.1,tsc_CC8.1,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>
```

## Adminer/PhpMyAdmin

```
adminer-
editor-
```

avec des Faux positifs possibles je pense

```
  <rule id="100008" level="6">
    <if_sid>31100,31108,31101</if_sid>
    <url>/adminer-|/editor-|editor.php|adminer.php</url>
    <description>Decouverte Adminer</description>
    <mitre>
      <id>T1595</id>
      <id>T1595.003</id>
      <id>T1190</id>
    </mitre>
    <group>attack,pci_dss_6.5,pci_dss_11.4,pci_dss_6.5.1,gdpr_IV_35.7.d,nist_800_53_SA.11,nist_800_53_SI.4,tsc_CC6.6,tsc_CC7.1,tsc_CC8.1,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>
```

pour PHPmyAdmin

```
nuclei -u http://192.168.57.2/ -include-templates http/exposed-panels -t http/exposed-panels/phpmyadmin-panel.yaml
```

```
  <rule id="100014" level="6">
    <if_sid>31100,31108,31101</if_sid>
    <url>phpmyadmin/|/phpMyAdmin|/phpma/</url>
    <description>Decouverte phpMyadmin</description>
    <mitre>
      <id>T1595</id>
      <id>T1595.003</id>
      <id>T1190</id>
    </mitre>
    <group>attack,pci_dss_6.5,pci_dss_11.4,pci_dss_6.5.1,gdpr_IV_35.7.d,nist_800_53_SA.11,nist_800_53_SI.4,tsc_CC6.6,tsc_CC7.1,tsc_CC8.1,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>

  <rule id="100015" level="7">
    <if_sid>100014</if_sid>
    <id>^200</id>
    <description>Accès phpMyadmin</description>
    <mitre>
      <id>T1595</id>
      <id>T1595.003</id>
      <id>T1190</id>
    </mitre>
    <group>attack,pci_dss_6.5,pci_dss_11.4,pci_dss_6.5.1,gdpr_IV_35.7.d,nist_800_53_SA.11,nist_800_53_SI.4,tsc_CC6.6,tsc_CC7.1,tsc_CC8.1,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>


  <rule id="100016" level="10" frequency="10" timeframe="60">
    <if_matched_sid>100014</if_matched_sid>
    <same_source_ip />
    <description>Scan phpMyadmin</description>
    <mitre>
      <id>T1595</id>
      <id>T1595.003</id>
      <id>T1190</id>
    </mitre>
    <group>attack,pci_dss_6.5,pci_dss_11.4,pci_dss_6.5.1,gdpr_IV_35.7.d,nist_800_53_SA.11,nist_800_53_SI.4,tsc_CC6.6,tsc_CC7.1,tsc_CC8.1,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
  </rule>



