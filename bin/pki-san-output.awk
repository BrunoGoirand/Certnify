# Decode the bounded OpenSSL SAN display into a typed, order-independent set.
# OpenSSL renders GeneralNames on the line following this anchored heading.
/^[ \t]*X509v3 Subject Alternative Name:/ {
  if (seen++) exit 1
  if (getline <= 0) exit 1
  sub(/^[ \t]+/, ""); sub(/[ \t]+$/, "")
  n=split($0, names, /, */)
  for (i=1; i<=n; i++) {
    v=names[i]
    if (v ~ /^DNS:/) {sub(/^DNS:/,"",v); print "DNS:" tolower(v)}
    else if (v ~ /^IP Address:/) {sub(/^IP Address:/,"",v); print "IP:" toupper(v)}
    else if (v ~ /^email:/) {sub(/^email:/,"",v); print "email:" v}
    else if (v ~ /^URI:/) {sub(/^URI:/,"",v); print "URI:" v}
    else exit 1
    if (v=="" || v ~ /[[:cntrl:]]/) exit 1
  }
}
