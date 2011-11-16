var assertsOk=[];
var assertsKo=[];


var GREEN="\033[5;34;42m"
var RED="\033[1;37;41m"
var BLACK="\033[00m"

function isTrue(msg){
  return GREEN+msg+BLACK;
}
function isFalse(msg){
  return RED+msg+BLACK;
}


function assert(msg,arg,exp){
 try{
  var res = eval.call(this,arg);
  if(exp == null){
   exp = true;
  }
  if( res == exp){
    print(isTrue(msg+arg));
    assertsOk.push(msg+arg);
  } else {
   print(isFalse(msg+arg));
   assertsKo.push(msg+arg);
  }  
  }catch(e){
   print(isFalse(msg+arg+' Exc:'+e));
   assertsKo.push(msg+arg);
    
  }
}

function printResults(){

  print("[Ok] "+assertsOk.join("\n"));
  
  print("[Ko] "+assertsKo.join(" "));
  
}
