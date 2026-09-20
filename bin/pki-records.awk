# Portable record parser. Inputs travel through ENVIRON, never awk -v escapes.
# Serial arithmetic is textual: no floating-point or shell integer conversion.
function fail(message) {
    print "[ERR] " FILENAME ":" FNR ": " message > "/dev/stderr"
    failed=1
    exit 1
}
function hex(s, t) {
    if (s !~ /^[0-9a-fA-F]+$/) fail("Invalid hexadecimal serial: " s)
    t=toupper(s); sub(/^0+/, "", t)
    if (t=="") t="0"
    if (length(t)>16) fail("Serial exceeds supported 64-bit unsigned range: " s)
    return t
}
function greater(a,b) {
    return length(a)>length(b) || (length(a)==length(b) && ("x" a)>("x" b))
}
function increment(s, i,n,out,carry) {
    carry=1; out=""
    for(i=length(s);i>0;i--) {
        n=index("0123456789ABCDEF",substr(s,i,1))-1+carry
        carry=(n==16); out=substr("0123456789ABCDEF",n%16+1,1) out
    }
    if(carry) out="1" out
    if(length(out)>16) fail("Serial range exhausted; refusing overflow")
    if(length(out)%2) out="0" out
    return out
}
function timestamp(s, y,m,d,h,mi,se,days) {
    if(s !~ /^[0-9]+Z$/ || (length(s)!=13 && length(s)!=15)) fail("Invalid ASN.1 time: " s)
    if(length(s)==13) {
        y=substr(s,1,2)+0; y+=(y<50?2000:1900); s=sprintf("%04d",y) substr(s,3)
    }
    y=substr(s,1,4)+0; m=substr(s,5,2)+0; d=substr(s,7,2)+0
    h=substr(s,9,2)+0; mi=substr(s,11,2)+0; se=substr(s,13,2)+0
    days=31
    if(m==4 || m==6 || m==9 || m==11) days=30
    if(m==2) days=28+(y%4==0 && (y%100!=0 || y%400==0))
    if(y<1 || m<1 || m>12 || d<1 || d>days || h>23 || mi>59 || se>59) fail("Invalid calendar time: " s)
    return s
}
function iso(s) {
    return substr(s,1,4) "-" substr(s,5,2) "-" substr(s,7,2) "T" substr(s,9,2) ":" substr(s,11,2) ":" substr(s,13,2) "Z"
}
function iso_time(s, t) {
    if(length(s)!=20 || substr(s,5,1)!="-" || substr(s,8,1)!="-" || substr(s,11,1)!="T" || substr(s,14,1)!=":" || substr(s,17,1)!=":" || substr(s,20,1)!="Z") fail("Invalid inventory UTC timestamp: " s)
    t=s; gsub(/[-:T]/,"",t); return timestamp(t)
}
function plain(s) { if(s ~ /[[:cntrl:]]/) fail("Control character in record field"); return s }
# Parse OpenSSL index slash-form names, including escaped separators and \xHH bytes.
# Commas are literal in slash form; unescaped plus separates multi-valued RDNs.
function cn_from_dn(s, i,c,key,value,invalue,cn,count,h,n) {
    if(substr(s,1,1)!="/") fail("Expected OpenSSL slash-form subject")
    key=""; value=""; invalue=0; cn=""; count=0
    for(i=2;i<=length(s)+1;i++) {
        c=(i<=length(s)?substr(s,i,1):"/")
        if(c=="\\") {
            if(i>=length(s)) fail("Incomplete subject escape")
            c=substr(s,++i,1)
            if(c=="x") {
                h=substr(s,i+1,2)
                if(length(h)!=2 || h !~ /^[0-9a-fA-F][0-9a-fA-F]$/) fail("Invalid subject hex escape")
                h=toupper(h); n=(index("0123456789ABCDEF",substr(h,1,1))-1)*16+index("0123456789ABCDEF",substr(h,2,1))-1
                if(n<32 || n==127) fail("Control byte in subject")
                c=sprintf("%c",n); i+=2
            }
        } else if(c=="/" || c=="+") {
            if(!invalue || key=="") fail("Malformed subject attribute")
            if(key=="CN") { cn=value; count++ }
            key=""; value=""; invalue=0; continue
        } else if(c=="=" && !invalue) { invalue=1; continue }
        if(invalue) value=value c; else key=key c
    }
    if(count!=1 || cn=="") fail("Subject must contain exactly one nonempty CN")
    return plain(cn)
}
BEGIN {
    FS="\t"; OFS="\t"; US=sprintf("%c",31)
    mode=ENVIRON["PKI_RECORD_MODE"]; wanted=ENVIRON["PKI_RECORD_CN"]
    now=ENVIRON["PKI_RECORD_NOW"]; max="0"
    if(mode=="inventory") {
        cs=ENVIRON["COL_SERIAL"]; ce=ENVIRON["COL_EXPIRES"]; cc=ENVIRON["COL_CN"]
        if(cs !~ /^[1-4]$/ || ce !~ /^[1-4]$/ || cc !~ /^[1-4]$/ || cs==ce || cs==cc || ce==cc) fail("Inventory columns must be distinct positions 1..4")
    }
    if(mode=="serial") current=hex(ENVIRON["PKI_RECORD_COUNTER"])
    if(mode=="serial-target") target=hex(ENVIRON["PKI_RECORD_SERIAL"])
}
{
    # Support CRLF without removing embedded control characters.
    sub(/\r$/, "")
    if($0=="" || (mode!="inventory" && $0 ~ /^#/)) next
    if(mode=="inventory") {
        if(NF!=4) fail("Expected exactly four inventory columns")
        for(i=1;i<=NF;i++) plain($i)
        serial=hex($cs); expiry=iso_time($ce); cn=$cc
        if(cn=="") fail("Empty inventory CN")
        output[++rows]=$cs US $ce US cn
        next
    }
    if(NF!=6) fail("Expected exactly six index columns (including empty revocation field)")
    for(i=1;i<=NF;i++) plain($i)
    if($1!="V" && $1!="R" && $1!="E") fail("Invalid index status: " $1)
    expiry=timestamp($2); serial=hex($4)
    if(seen["s" serial]++) fail("Duplicate numeric serial: " $4)
    if($1=="R") {
        split($3,rev,","); ignored=timestamp(rev[1])
    } else if($3!="") fail("Unexpected revocation data on non-revoked row")
    if($5=="") fail("Empty certificate locator")
    cn=cn_from_dn($6)
    if(greater(serial,max)) max=serial
    if(mode=="serial-target" && ("s" serial)==("s" target)) {
        if(ENVIRON["PKI_REQUIRE_CN"]=="1" && ("n" cn)!=("n" wanted)) fail("Artifact belongs to a different CN")
        output[++rows]=$4 US $5
    }
    if(mode=="list" && ($1=="V" || ($1=="R" && ENVIRON["INCLUDE_REVOKED"]=="1") || ($1=="E" && ENVIRON["INCLUDE_EXPIRED"]=="1")))
        output[++rows]=$4 OFS iso(expiry) OFS cn OFS $5
    if(mode=="remaining" && $1=="V" && ("t" expiry)>("t" now)) remaining++
    if(mode=="duplicates" && $1=="V" && ("t" expiry)>("t" now) && ("n" cn)==("n" wanted))
        output[++rows]=$4 US $5
    if(mode=="revoke" && ("n" cn)==("n" wanted)) {
        history[++hist]=$4
        if($1=="V" && ("t" expiry)>("t" now)) candidates[++matches]=$4
    }
}
END {
    if(failed) exit 1
    if(mode=="remaining") print remaining+0
    else if(mode=="serial") {
        if(!greater(current,max)) print increment(max)
        else print ENVIRON["PKI_RECORD_COUNTER"]
    } else if(mode=="revoke") {
        if(matches==1) print candidates[1]
        else if(matches>1) {
            message="Ambiguous CN; use FILE or SERIAL. Candidates:"
            for(i=1;i<=matches;i++) message=message " " candidates[i]
            fail(message)
        } else if(hist==1) print history[1]
        else if(hist>1) {
            message="No unique historical certificate for CN; use FILE or SERIAL. Candidates:"
            for(i=1;i<=hist;i++) message=message " " history[i]
            fail(message)
        }
        else fail("No exact CN in index; use FILE or SERIAL")
    } else for(i=1;i<=rows;i++) print output[i]
}
