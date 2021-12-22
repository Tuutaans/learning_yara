rule jndi_instance_finder
  {
    meta:
      author = "tutaans"
      description = "trying to find out jndi lookup"
      created = "12/22/2021"
    strings:
      $jndiwildcard = "${jndi:*"
      $jndvar = "jnd" wide ascii nocase base64
      $envvar = "env" wide ascii nocase base64
      $ldapvar = "ldap:*" wide ascii nocase base64
      $dnsvar = "dns:*" wide ascii nocase base64
      $datevar = "date:*" wide ascii nocase base64


      
    conditions:
      any of them
  }
