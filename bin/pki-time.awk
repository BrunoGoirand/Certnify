# UTC calendar conversion, independent of GNU date/awk extensions (MIT).
function leap(y) {return y%4==0 && (y%100!=0 || y%400==0)}
function dim(y,m) {return m==2 ? 28+leap(y) : (m==4||m==6||m==9||m==11 ? 30 : 31)}
function fail() {print "[ERR] Invalid certificate UTC date" > "/dev/stderr"; exit 1}
function before(y) {y--; return 365*y+int(y/4)-int(y/100)+int(y/400)}
function encode(t, d,y,m,h,mi,s) {
    if(t<0 || t>253402300799) fail()
    d=int(t/86400); s=t%86400; y=1970
    while(d>=365+leap(y)) {d-=365+leap(y); y++}
    m=1; while(d>=dim(y,m)) {d-=dim(y,m); m++}
    h=int(s/3600); s%=3600; mi=int(s/60); s%=60
    return sprintf("%04d%02d%02d%02d%02d%02dZ",y,m,d+1,h,mi,s)
}
BEGIN {
    if(ENVIRON["PKI_TIME_MODE"]=="encode") {
        v=ENVIRON["PKI_TIME_VALUE"]
        if(v!~/^[0-9]+$/) fail()
        print encode(v+0); exit
    }
}
/^notAfter=/ {
    sub(/^notAfter=/,""); n=split($0,a,/[ :]+/)
    split("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec",months," ")
    m=0; for(i=1;i<=12;i++) if(a[1]==months[i]) m=i
    if(n!=7 || !m || a[7]!="GMT") fail()
    for(i=2;i<=6;i++) if(a[i]!~/^[0-9]+$/) fail()
    y=a[6]+0; d=a[2]+0
    if(y<1970 || y>9999 || d<1 || d>dim(y,m) || a[3]>23 || a[4]>59 || a[5]>59) fail()
    days=before(y)-before(1970)+d-1
    for(i=1;i<m;i++) days+=dim(y,i)
    printf "%.0f\t%04d-%02d-%02dT%02d:%02d:%02dZ\n", days*86400+a[3]*3600+a[4]*60+a[5],y,m,d,a[3],a[4],a[5]
    found++
}
END {if(ENVIRON["PKI_TIME_MODE"]!="encode" && found!=1) exit 1}
