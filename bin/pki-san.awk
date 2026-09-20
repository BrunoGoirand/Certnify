function fail(v) {print "[ERR] Invalid " kind " SAN: " v > "/dev/stderr"; exit 1}
function dns(v, a,n,i) {
 if(length(v)>253) return 0
 sub(/\.$/,"",v); n=split(v,a,".")
 for(i=1;i<=n;i++) if(!(i==1 && a[i]=="*" && n>1) && (length(a[i])<1 || length(a[i])>63 || a[i]!~/^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$/)) return 0
 return n>0
}
function ipv4(v, a,n,i) {n=split(v,a,"."); if(n!=4) return 0; for(i=1;i<=4;i++) if(a[i]!~/^[0-9]+$/ || length(a[i])>3 || a[i]+0>255) return 0; return 1}
function ip(v, a,n,i,compressed,count,last) {
 if(index(v,":")==0) return ipv4(v)
 if(v!~/^[0-9A-Fa-f:.]+$/ || v~/:::/) return 0
 compressed=index(v,"::")>0
 if(compressed && substr(v,index(v,"::")+2)~/::/) return 0
 if(!compressed && (v~/^:/ || v~/:$/)) return 0
 n=split(v,a,":"); count=0
 for(i=1;i<=n;i++) {
   if(a[i]=="") continue
   if(index(a[i],".")) {if(i!=n || !ipv4(a[i])) return 0; count+=2}
   else {if(length(a[i])>4 || a[i]!~/^[0-9A-Fa-f]+$/) return 0; count++}
 }
 return compressed ? count<8 : count==8
}
BEGIN {
 kind=ENVIRON["PKI_SAN_TYPE"]; raw=ENVIRON["PKI_SAN_VALUES"]
 if(raw=="") exit 0
 n=split(raw,items,",")
 for(j=1;j<=n;j++) {
   v=items[j]; gsub(/^ +| +$/,"",v)
   if(v=="" || v~/[[:cntrl:]\\"]/ || v~/[[:space:]]/) fail(v)
   if(kind=="DNS" && !dns(v)) fail(v)
   if(kind=="IP" && !ip(v)) fail(v)
   if(kind=="EMAIL") {
     k=split(v,parts,"@"); if(k!=2 || parts[1]=="" || parts[1]~/[<>():;\[\]]/ || !dns(parts[2]) || parts[2]~/\*/) fail(v)
   }
   if(kind=="URI" && v!~/^[A-Za-z][A-Za-z0-9+.-]*:.+$/) fail(v)
   if(!seen[v]++) out=out (out==""?"":",") v
 }
 print out
}
