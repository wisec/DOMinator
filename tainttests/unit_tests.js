load('./UnitTest.js');

var ts=String.newTainted("ddddd\nddd","dd")   
var zerolengthtainted=String.newTainted("","zerolength")   
var zerolengthuntaintedNewString=new String("");
var zerolengthuntainted="";
ts.tainted

__domIntruderObj={domILog:function(a,b,c,d){print(a,b,c,d)}};


///////////////////////////
// [String in Object Test]

var obj={x:ts,c:zerolengthuntainted};
 if(ts in obj) print ("ok")
assert("String in Object test ","obj.x.tainted ",true); 
assert("String in Object test ","obj.c.tainted",false);

var aas=String.newTainted("d","dd")   
var obj={d:ts,c:zerolengthuntainted};

assert("String in Object test ","aas in obj",true); 
assert("String in Object test ","'d' in obj",true);


///////////////////////////
/// [Strings in object , tainted keys ]

var elName='aaaaaaaaaaaddddddd'
var pObj={elName:"test1234"}

var obj={anElement123456:zerolengthuntainted};
obj.__proto__=pObj; 

var taintedKey=String.newTainted( elName,"aTaintedKey");
obj[taintedKey]="someValue"

Object.keys(obj)[1].tainted 
assert("String in Object test Object.keys(obj)[1].tainted ","'d' in obj",true);

///////////////////////////
/// [ Object with tainted keys ]
// Yet to implement
var elName='aaaaaaaaaaaddddddd'
var pObj={elName:"test1234"}

var obj={anElement123456:zerolengthuntainted};
obj.__proto__=pObj; 

var taintedKey=String.newTainted( elName,"aTaintedKey");
obj[taintedKey]="someValue"

Object.keys(obj)[1].tainted 
assert("String in Object  tainted keys ","Object.keys(obj)[1].tainted",true);




///////////////////////////
//[String Concat Test]

var ats=String.newTainted("aaa"+"gggg","ddd")
var concstr1=ts+ats;
assert( "String Concat test ","concstr1.tainted",true)

var concstr2=ts+ats+'dddd';
assert( "String Concat test ","concstr2.tainted",true)

var concstr3='dddd'+ts+ats;
assert("String Concat test ","concstr3.tainted",true)

var concstr4=ts+'dddd'+ats;
assert("String Concat test ","concstr4.tainted",true)

var concstr5zl=zerolengthtainted+''+zerolengthuntainted;
assert("String Concat test ","concstr5zl.tainted",true)

///////////////////////////
//[String Quote Test]

var tsq=ts.quote();
assert("String Quote test ","tsq.tainted",true)

var tsq2= concstr4.quote();
assert("String Quote test ","tsq2.tainted",true)

var tsq3= concstr5zl.quote();
assert("String Quote test ","tsq3.tainted",true)

//////////////////////////
// [String escape test]
var fun=escape
var ets=fun(ts);
assert("String escape test ","ets.tainted",true)

var ets1= fun(zerolengthtainted );
assert("String escape test ","ets1.tainted",true);

var ets2= fun(zerolengthuntainted );
assert("String escape test ","ets2.tainted",false)

//////////////////////////
// [String decodeURIComponent test]
var fun= decodeURIComponent
var ets=  fun(ts);
assert("String decodeURIComponent test ","ets.tainted",true)

var ets1= fun(zerolengthtainted );
assert("String decodeURIComponent test ","ets1.tainted",true);

var ets2= fun(zerolengthuntainted );
assert("String decodeURIComponent test ","ets2.tainted",false)

//////////////////////////
// [String decodeURI test]
var fun= decodeURI
var ets=  fun(ts);
assert("String decodeURI test ","ets.tainted",true)

var ets1= fun(zerolengthtainted );
assert("String decodeURI test ","ets1.tainted",true);

var ets2= fun(zerolengthuntainted );
assert("String decodeURI test ","ets2.tainted",false)

//////////////////////////
// [String encodeURI test]
var fun= encodeURI
var ets=  fun(ts);
assert("String encodeURI test ","ets.tainted",true)

var ets1= fun(zerolengthtainted );
assert("String encodeURI test ","ets1.tainted",true);

var ets2= fun(zerolengthuntainted );
assert("String encodeURI test ","ets2.tainted",false)

//////////////////////////
// [String encodeURIComponent test]
var fun= encodeURIComponent
var ets=  fun(ts);
assert("String encodeURIComponent test ","ets.tainted",true)

var ets1= fun(zerolengthtainted );
assert("String encodeURIComponent test ","ets1.tainted",true);

var ets2= fun(zerolengthuntainted );
assert("String encodeURIComponent test ","ets2.tainted",false)

//////////////////////////
// [String trim test]
var fun= String.trim
var ets=  fun(ts);
assert("String trim test ","ets.tainted",true)

var ets1= fun(zerolengthtainted );
assert("String trim test ","ets1.tainted",true);

var ets2= fun(zerolengthuntainted );
assert("String trim test ","ets2.tainted",false)

//////////////////////////
// [String toUpperCase test]
var fun=  String.toUpperCase
var ets=  fun(ts);
assert("String toUpperCase test ","ets.tainted",true)

var ets1= fun(zerolengthtainted );
assert("String toUpperCase test ","ets1.tainted",true);

var ets2= fun(zerolengthuntainted );
assert("String toUpperCase test ","ets2.tainted",false)

//////////////////////////
// [String toLowerCase test]
var fun=  String.toLowerCase
var ets=  fun(ts);
assert("String toLowerCase test ","ets.tainted",true)

var ets1= fun(zerolengthtainted );
assert("String toLowerCase test ","ets1.tainted",true);

var ets2= fun(zerolengthuntainted );
assert("String toLowerCase test ","ets2.tainted",false)

//////////////////////////
// [String substring test]

var ets=  ts.substring(1,3);
assert("String substring test ","ets.tainted",true)

var ets1= zerolengthtainted.substring(1,3) ;
assert("String substring test ","ets1.tainted",true);

var ets2=  zerolengthuntainted.substring(1,3) ;
assert("String substring test ","ets2.tainted",false)

//////////////////////////
// [String substr test]

var ets=  ts.substr(1,3);
assert("String substr test ","ets.tainted",true)

var ets1= zerolengthtainted.substr(1,3) ;
assert("String substr test ","ets1.tainted",true);

var ets2=  zerolengthuntainted.substr(1,3) ;
assert("String substr test ","ets2.tainted",false)

//////////////////////////
// [String slice test]

var ets=  ts.slice(1);
assert("String slice test ","ets.tainted",true)

var ets1= zerolengthtainted.slice(1) ;
assert("String slice test ","ets1.tainted",true);

var ets2=  zerolengthuntainted.slice(1)  ;
assert("String slice test ","ets2.tainted",false)

//////////////////////////
// [String slice test]

var splitar = ts.split("\n");
assert("String slice test ","splitar[0].tainted",true);
assert("String slice test ","splitar[1].tainted",true);
var tssplit=String.newTainted("\n","dd").split('\n');  
assert("String slice test ","tssplit[0].tainted",true);
assert("String slice test ","tssplit[1].tainted",true);

///////////////////////////
/// [single char test]
var nsts=new String(ts);
assert("Single char test","nsts[1].tainted",true);
assert("Single char test","ts[1].tainted",true);

//////////////////////////
/// [String match test]
var nsts=new String(String.newTainted("aaa|bb|cc|dd","sss"));
var res=nsts.match(/([^|]+)/g);
for(var i=0,l=res.length;i<l;i++)
 assert("String match test","res["+i+"].tainted",true);

var res=nsts.match("bb")
for(var i=0,l=res.length;i<l;i++)
 assert("String match test","res["+i+"].tainted",true);
nsts=zerolengthtainted
var res=nsts.match("")
for(var i=0,l=res.length;i<l;i++)
 assert("String match test","res["+i+"].tainted",true);

//////////////////////////
/// [String charAt test]
var res= ts.charAt(2);
assert("String match test","res.tainted",true);
var res= ts.charAt(122);
assert("String match test","res.tainted",true);

//////////////////////////
/// [String replace test]
var nsts=new String(String.newTainted("aaa|bb|cc|dd","sss"));
var res=nsts.replace(/([^|]+)/g,"xX");
assert("String replace test","res.tainted",true);

var res=nsts.replace(/gg/g,"xX");
res.tainted 
assert("String replace test","res.tainted",true);

var res=nsts.replace(/.*/g,"");   
res.tainted
assert("String replace test","res.tainted",true);

var res=nsts.replace(/.*/g, String.newTainted("","sss"));   
res.tainted
assert("String replace test","res.tainted",true);

var res=nsts.replace(/.*/g, String.newTainted("d","sss"));   
res.tainted
assert("String replace test","res.tainted",true);

var res=nsts.replace(/.*/, String.newTainted("d","sss"));   
res.tainted
assert("String replace test","res.tainted",true);

var res="aaabc".replace(/aa/,String.newTainted("fa","ddd")); 
res.tainted
assert("String replace test","res.tainted",true);

var res=nsts.replace("a", "d");  
assert("String replace test","res.tainted",true);

res=nsts.replace("a", function(a,b,c){return "d"});
assert("String replace test","res.tainted",true);

// This case was not covered by DOMinator 3.6
res=nsts.replace(/a/, function(a,b,c){print ("aaa");return "d"});
assert("String replace test","res.tainted",true);

// This case was not covered by DOMinator 3.6
res=nsts.replace(/a/, function(a,b,c){var cc=String.newTainted("d","test");return cc});
assert("String replace test","res.tainted",true);

{
m=["b"];
b=String.newTainted("<b>ff","cfcc");
c=b.replace(/<\/?(.+?)\/?>/gi,function (a, f) {print(a.tainted+' '+f+' '+f.tainted) ;return m.indexOf(f)!=-1 ? a : ""; })
print(c+' '+c.tainted)
} 
(function(){
function dd(c){ return function(a,b,c){var ob={"a":"d"}; return c+' '+ob[a]}
}
res=nsts.replace(/a/g, dd('v'));
assert("String replace test Closure","res.tainted",true);
})()


//////////////////////
// Array operations
nsts=String.newTainted("abcdefghilmnopqrstuvz","testSource");
nsts2=String.newTainted("1234567890","testSource1");
unt="AAAAAAAAAAAAAAAAAAAAAA";

var v=[unt,nsts,nsts2];
var vv=[false,true,true]

// Array for each
var j=0;
for each(var i in v){
 assert("Array for each "+String.unTaint(i)+".tainted ",i.tainted,vv[j++]);
}

// Array map
j=0;
var newAr=v.map(function(a){return "A string "+a})
for each(var i in  newAr){
 assert("Array map new Array "+String.unTaint(i)+".tainted ",i.tainted,vv[j++]);
}

// Array join
var ts=String.newTainted("ddddd\nddd","dd")   
c='ddd'+ts
cv=[c,ts,'dddd']
v=cv.join(' ')
assert("Array join ","v.tainted",true);

String.getTaintInfo(v) 

///////////////////////////
/// Array Objects.
///var ts=String.newTainted("ddddd\nddd","aSource")   
///var ts2=String.newTainted("taintedKey","keySource")   
///c='ddd'+ts
///cv=[c,ts,'dddd'];
///
///cv[c] = 2;
////////////////////
/// Eval tests
var tse=String.newTainted("test","dd")   
__domIntruderObj={domILog:function(a,b,c,d){print(a,b,c,d)}};
eval("print('"+tse+"')")


////////////////////
/// Switch / case construct logging helper
var switchString=String.newTainted("test","dd")   

__domIntruderObj={domILog:function(a,b,c,d){print(a,b,c,d)}};
switch(switchString){
 case "test": print ("ok");
    break;
 default:  
       break;
}



printResults();


