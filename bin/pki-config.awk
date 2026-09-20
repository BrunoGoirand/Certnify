# Validate generated CA path bindings; rebind only after a controlled move.
function fail(s) { print "[ERR] " FILENAME ": " s > "/dev/stderr"; bad=1; exit 1 }
BEGIN {
 base=ENVIRON["PKI_CONFIG_BASE"]; replacement=ENVIRON["PKI_CONFIG_NEW"]
 paths["certs"]="certs"; paths["crl_dir"]="crl"; paths["database"]="index.txt"
 paths["new_certs_dir"]="newcerts"; paths["certificate"]="certs/ca.cert.pem"
 paths["serial"]="serial"; paths["crlnumber"]="crlnumber"; paths["crl"]="crl/ca.crl.pem"
 paths["private_key"]="private/ca.key.pem"; paths["RANDFILE"]="private/.rand"
}
{
 line=$0
 if(line ~ /^[ \t]*\.include/) fail("Includes require explicit configuration migration")
 if(line ~ /^[ \t]*\[/) { section=line; gsub(/[ \t\[\]]/,"",section) }
 if(line ~ /^[ \t]*[^#;][^=]*=/) {
   key=line; sub(/=.*/,"",key); gsub(/^[ \t]+|[ \t]+$/,"",key)
   value=line; sub(/^[^=]*=[ \t]*/,"",value); sub(/[ \t]+$/,"",value)
   if(section=="ca" && key=="default_ca" && value!="CA_default") fail("Unsupported default_ca binding")
   if(section=="CA_default" && (key=="dir" || key in paths)) {
     if(seen[key]++) fail("Duplicate CA path: " key)
     if(key=="dir") {
       if(value!=base) fail("Stale authority binding: " value " (expected " base ")")
       if(replacement!="") line="dir = " replacement
     } else {
       if(value!="$dir/" paths[key] && value!=base "/" paths[key]) fail("Unsafe CA path " key "=" value)
       if(replacement!="" && value==base "/" paths[key]) line=key " = " replacement "/" paths[key]
     }
   }
 }
 print line
}
END {
 if(bad) exit 1
 if(!seen["dir"]) fail("Missing CA_default dir")
 for(key in paths) if(!seen[key]) fail("Missing CA path: " key)
}
