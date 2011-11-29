#ifdef TAINTED
#include "jsapi.h"
#include "jsstr.h"
#include "jscntxt.h"
#include "jsgcmark.h"
#include "taint.h"
#include "jsscope.h" 
#include "vm/Stack.h" 
#include "jsarray.h"
#include "jsvalue.h"
#include "jsgc.h"
//#include "sqlite3.h"

#define DOMINATOROBJ "__domIntruderObj"
#define DOMINATORLOG "domILog"

#define TAINTROOT "TAINTROOT"

const char *const OpNames[] = {"NONE","GET","SET","SOURCE","SINK","CHARAT","SUBSTRING","LOWERCASE","UPPERCASE",
                               "JOIN","SPLIT","SLICE","REPLACE","REGEXP","CONCAT","CONCATLEFT","CONCATRIGHT",
                               "ESCAPE","UNESCAPE","ENCODEURI","DECODEURI","ENCODEURICOMPONENT","DECODEURICOMPONENT",
                               "TRIM","TAGIFY","QUOTE","DEPEND","ATOB","BTOA"};
                               
const int OpSize=sizeof(OpNames)/sizeof(OpNames[0]);
void traverseInfoTaintDep(JSContext *cx ,InfoTaintDep *ITD,JSString *str,JSObject *obj,JSObject *depArr);

 

static int count=0;


//XXXStefano Note:
//  these two methods were a test in AddNamedRoot implementation.
//  there's a problem with cross compartments since the tsCollector
//  must belong to a particulae cx (the first one).
//  So, at least for now, they are commented out.
/* 
JSBool createTSCollector(JSContext *cx){
  cx->runtime->tsCollector = JS_NewArrayObject(cx,0,NULL);
  JS_AddNamedObjectRoot(cx,&cx->runtime->tsCollector,"tsCollector");
  return JS_TRUE;
}

JSBool addStringToCollector(JSContext *cx,JSString *str){
    jsval v=STRING_TO_JSVAL(str);
    if(!cx->runtime->tsCollector){
      createTSCollector(cx);
    }
    JSObject *obj=cx->runtime->tsCollector;
    JS_SetElement( cx,obj ,obj->getArrayLength(), &v );
    return JS_TRUE;
}
*/

void traverseInfoTaintEntry(JSContext *cx ,InfoTaintEntry *ITE,JSObject *obj){
  InfoTaintEntry *tmpITE;
  jsval v;
  JSObject *depArray;
  
  v=STRING_TO_JSVAL(ITE->str);
  JS_SetProperty(cx,obj,"val",&v);
  if(ITE->source){
   v=STRING_TO_JSVAL(ITE->source);
   JS_SetProperty(cx,obj,"source",&v);
  }
  v=STRING_TO_JSVAL(JS_NewStringCopyZ(cx,OpNames[(int)ITE->op]));
  JS_SetProperty(cx,obj,"op",&v);
  
  if(ITE->dep && ITE->op <= OpSize ){
      depArray=JS_NewArrayObject(cx,0,NULL); //JS_DefineObject(cx,obj,"dep",&js_ArrayClass,NULL,0);
      v=OBJECT_TO_JSVAL(depArray);
      JS_SetProperty(cx,obj,"dep",&v);
      traverseInfoTaintDep( cx , ITE->dep,ITE->str, obj,depArray);
  }
}

void traverseInfoTaintDep(JSContext *cx ,InfoTaintDep *ITD,JSString *str,JSObject *obj,JSObject *depArr){
  InfoTaintDep *tmpITD;
  InfoTaintEntry *tmpITE;
  JSObject *entryObj;
  jsval v;
  int i;
  
  i=0;
  tmpITD=ITD;
  while(tmpITD&&tmpITD->entry ){
   if(tmpITD->entry){

      
      entryObj=JS_NewObject(cx,NULL,NULL,NULL);
     
      v=INT_TO_JSVAL(tmpITD->spos);
      JS_SetProperty(cx,entryObj,"startPos",&v);
     
      v=INT_TO_JSVAL( tmpITD->epos);
      JS_SetProperty(cx,entryObj,"endPos",&v);
     
      v=OBJECT_TO_JSVAL(entryObj );
      JS_SetElement(cx,depArr,i,&v);
     
      traverseInfoTaintEntry(cx ,tmpITD->entry,entryObj);
      i++;
   }
   tmpITD=tmpITD->next; 

  }
}

InfoTaintEntry *findTaintEntry(JSContext *cx,JSString/*o jsval* */ *str){
  InfoTaintEntry *tmpTaint= cx->runtime->rootITE;
  if(!tmpTaint){
   return NULL;
  }
  do {
     if(tmpTaint->str==str){
      return tmpTaint;
     }
     tmpTaint=tmpTaint->next;
  } while(tmpTaint);
  return NULL; 
}
/*
JSBool hasUnGCedDependencies(JSContext *cx ,InfoTaintEntry *ITE ){
  InfoTaintDep *tmpITD;
  InfoTaintEntry *tmpITE=ITE;
  tmpITD=tmpITE->dep;
  return JS_TRUE;
  while(tmpITD){
   if(tmpITD->entry->pGTOEntry->gObj || hasUnGCedDependencies( cx , tmpITE ) ){
     return JS_TRUE;
   }
   tmpITE=tmpITD->entry;
   
  }
  return JS_FALSE;
}
////////////////////////////////
// GlobalObjectWithTainting methods
//  GlobalObjectWithTainting is a list
//  which is used as storage for globalObjects 
//  tainted Strings depend on.
//  Until the globlaObject is GCed, all tainted string 
//  need to be alive. (no GC)
//  This approach should solve memory use issues on DOMinator.

GlobalObjectWithTainting *
 findGlobalObjectEntry(JSContext *cx,JSObject *obj){
  GlobalObjectWithTainting  *tmpObj= cx->runtime->rootITG;
  if(!tmpObj ){
   return NULL;
  }
  do {
     if(tmpObj->gObj==obj){
      return tmpObj;
     }
     tmpObj=tmpObj->next;
  } while(tmpObj);
  return NULL; 
}

GlobalObjectWithTainting *
 addGlobalObjectEntry(JSContext *cx,JSObject *obj){
  GlobalObjectWithTainting  *tmpObj= cx->runtime->rootITG;
  GlobalObjectWithTainting  *newObj=NULL;

  if(tmpObj->gObj==(JSObject *)-1){ // rootITG is invalid (first instantiation)
   tmpObj->gObj=obj;
   return tmpObj;
  }
  newObj=(GlobalObjectWithTainting  *) JS_malloc(cx, (size_t) sizeof( GlobalObjectWithTainting));
  if(!newObj)
   return NULL;

  newObj->gObj=obj;
  newObj->next= tmpObj;
  cx->runtime->rootITG=newObj;
  return newObj; 
}

JSBool
 removeGlobalObjectEntry(JSContext *cx,JSObject *obj){
  GlobalObjectWithTainting  *tmpObj= cx->runtime->rootITG  ;
  GlobalObjectWithTainting  *prevObj= cx->runtime->rootITG;
  
  if(!tmpObj ){
   return JS_FALSE;
  }
  
  do {
     if(tmpObj->gObj==obj){
         break; 
     }
     prevObj=tmpObj;
     tmpObj=tmpObj->next;
  } while(tmpObj);
  
  if(tmpObj){
   prevObj->next=tmpObj->next;
   free(tmpObj);
   return JS_TRUE; 
  }
  return JS_FALSE;
}
////////////////////////////////
// End GlobalObjectWithTainting methods
//
*/


/// TaintInfos
JSObject *getInfoFromTaintTable(JSContext *cx,JSString *str ){
  JSObject * obj;
  InfoTaintEntry *tmpITE;
  char *name=NULL;                                            
   JSAtom *atom;
   JSString *atom_str;
 
  atom_str=str;
  if(!(tmpITE=findTaintEntry(cx, atom_str))){
   return NULL;
  }
  if(tmpITE){
    //traverseInfoTaintDep(cx , tmpITE->dep);
    obj=JS_NewObject(cx,NULL,NULL,NULL);
    traverseInfoTaintEntry(cx , tmpITE, obj);
  }
  
  return  obj;
}

// TaintInfo Insert Remove Operations
InfoTaintEntry *addToTaintTable(JSContext *cx,JSString/*o jsval* */ *str,JSString *source,TaintOp taintop){
   InfoTaintEntry *newITE,*tmpITE;
   JSAtom *atom;
   JSString *atom_str;
   count++;

   atom_str=str;
   #ifdef DEBUG
   if(cx->globalObject){
    printf("globalObject\n ");
    js_DumpObject(cx->globalObject->getParent());
   }
   #endif
   if( (tmpITE=findTaintEntry(cx, atom_str)) && tmpITE->op==taintop  ){
          return tmpITE;
   }
  // addStringToCollector(cx,atom_str);
   if(!cx->runtime || !cx->runtime->rootITE){
     return NULL;
   }
   if(cx->runtime->rootITE->str==NULL){
     newITE=cx->runtime->rootITE;
     newITE->str= atom_str;
     newITE->source=source;
     newITE->op=taintop;
     newITE->dep=NULL;
     
   }else{
     newITE=(InfoTaintEntry  *) JS_malloc(cx, (size_t) sizeof(InfoTaintEntry));

     if(!newITE){
      return NULL;
     }

     newITE->str=atom_str;
     newITE->source=source;
     newITE->op=taintop;
     newITE->dep=NULL;

     tmpITE=cx->runtime->rootITE;
     newITE->next=tmpITE;
     cx->runtime->rootITE=newITE;
   } 
 /*  if(cx && cx->globalObject){
     GlobalObjectWithTainting *gObj=findGlobalObjectEntry(cx,cx->globalObject->getParent());
     if(!gObj){
        gObj=addGlobalObjectEntry( cx, cx->globalObject->getParent());
     }
       newITE->pGTOEntry=gObj;
   }else{
     newITE->pGTOEntry=NULL;
   }*/
  /* if(cx && cx->globalObject)
    newITE->parentGObj= cx->globalObject->getParent();
   else
    newITE->gObj= NULL;*/
   newITE->refCount=0;
   return newITE;
}

InfoTaintDep *addToInfoTaintDep(JSContext *cx,InfoTaintEntry *entryDep,InfoTaintDep *next){
  InfoTaintDep *newITD;
  
  newITD=(InfoTaintDep *) JS_malloc(cx, (size_t) sizeof(InfoTaintDep));
  if(!newITD)
   return NULL;
  
  if(next)
   newITD->next=next;
  else
   newITD->next=NULL;
  
  if(entryDep){
   newITD->entry=entryDep;
   entryDep->refCount++;
  }
  else
   newITD->entry=NULL;
  
  newITD->spos=-1;
  newITD->epos=-1;
  newITD->desc=NULL;
  return newITD;
}

JSBool removeInfoTaintEntryDeps( InfoTaintEntry *ITE){
  InfoTaintEntry *tmpITE=ITE;
  InfoTaintDep *tmpITD,*nextITD;
  if(ITE){
    tmpITD=nextITD=ITE->dep;
    
    while(tmpITD){
       JS_ASSERT(tmpITD->entry->refCount>0);
       tmpITD->entry->refCount--;
       nextITD=tmpITD->next;
       free(tmpITD);
       tmpITD=nextITD;
    }
    ITE->dep=NULL;
    return JS_TRUE;
    
  }else{
   return JS_TRUE;
  } 
  
}


//End TaintInfo Insert Remove

// Start String Track Taint 



JSBool 
addTaintInfoOneArg(JSContext *cx,JSString *argStr,JSString *retStr,char *desc,TaintOp op){
 InfoTaintEntry *TE,*TTE;
 InfoTaintDep *TTD;
 

 TE=findTaintEntry( cx, argStr);
 if(!TE){ //if it's not found, maybe we have to create it?
  return JS_FALSE;
 }
 
 TTE=addToTaintTable( cx, retStr,NULL,op);
 if(!TTE){
  return JS_FALSE;
 }
 TTD=addToInfoTaintDep(cx,TE,TTE->dep);
 if(!TTD){
  return JS_FALSE;
 }
 TTD->desc=desc;
 TTE->dep=TTD;
 return JS_TRUE;
}

JSBool 
addTaintInfoConcat(JSContext *cx,JSString *argStr,JSString *retStr,int start,int end,TaintOp op){
 InfoTaintEntry *TE,*TTE;
 InfoTaintDep *TTD;

 TE=findTaintEntry( cx, argStr);
 if(!TE){ //Forse se non lo trova dobbiamo crearlo?
  return JS_FALSE;
 }
 
 TTE=addToTaintTable( cx, retStr,NULL,op);
 if(!TTE){
  return JS_FALSE;
 }

 TTD=addToInfoTaintDep(cx,TE,TTE->dep);
 if(!TTD){
  return JS_FALSE;
 }
 TTD->spos=start;
 TTD->epos=end;
 
 TTD->desc=NULL;
 TTE->dep=TTD;
 
 return JS_TRUE; 
}
/*******************
 XXXStefano Note:
 GC Callback solution is used 
 in order to prevent GC to free 
 tainted strings.
 We need them alive in order to trace back 
 Taint operations.
*********************/
//String Track Taint 
static struct GCManagerInfo{
  JSGCCallback _oldCallback;
} GCMI;

static JSBool markLiveObjects(JSContext *cx, JSGCStatus theStatus){
 InfoTaintEntry *tmpITE ,*prevITE;
 jsuint isFirst=1;
 JSBool last;
// JSClass *clasp;
 if (JSGC_MARK_END!=theStatus){
     return GCMI._oldCallback?GCMI._oldCallback(cx,theStatus):JS_TRUE;
 }
 if(cx){
// JSTracer *trc= cx->runtime->gcMarkingTracer;
  js::GCMarker trc(cx);
  #ifdef DEBUG
  printf("GCCalled\n");
  #endif
  tmpITE= cx->runtime->rootITE;
  prevITE= cx->runtime->rootITE;
  
  while(tmpITE) {
   #ifdef DEBUG
     printf("Entering GC checks\n");
   #endif
      //  GlobalObjectWithTainting *tmpGTO=tmpITE->pGTOEntry;
      int refCount=-1;

        if (tmpITE->source && JS_IsAboutToBeFinalized(cx, tmpITE->source )) {
              #ifdef DEBUG
              printf("Source: \n");js_DumpString(tmpITE->source);
              #endif
              JS_ASSERT(tmpITE->refCount>=0);
              if(!tmpITE->refCount){
                 refCount=0;
                 printf("String: DONT keep: \n");
              } else {
         #ifdef DEBUG
          printf("SourcE: KEEP, refCount: %d\n", tmpITE->refCount);
         #endif
               js::gc::MarkGCThing(&trc, (tmpITE->source) , "Taint Info" );
              }
       }
        
        if ( tmpITE->str && JS_IsAboutToBeFinalized(cx, tmpITE->str)  /*(tmpGTO->gObj || hasUnGCedDependencies(cx,tmpITE))&& !tmpITE->gObj && hasUnGCedDependencies()*/ ) {
              #ifdef DEBUG
              printf("str: \n");js_DumpString(tmpITE->str);
             #endif
 
              if(!tmpITE->refCount){
                 refCount=0; 
                 printf("String: DONT keep: \n");
                 
             } else {
              
         #ifdef DEBUG
          printf("String: KEEP, refCount: %d\n",tmpITE->refCount);
         #endif
                js::gc::MarkGCThing(&trc,  tmpITE->str, "Taint Info" );
              }
        }
        if(!refCount){
         InfoTaintEntry *_tmpITE=tmpITE;
         #ifdef DEBUG
          printf("Ok, refCount: %d\n",refCount);
         #endif
         removeInfoTaintEntryDeps(tmpITE);
         if(isFirst){
           if(!tmpITE->next){ //it's the last one. We don't want to free it but only null its attrs
            cx->runtime->rootITE->str=NULL;
            cx->runtime->rootITE->source=NULL;
            cx->runtime->rootITE->refCount=0;
            cx->runtime->rootITE->dep=NULL;
            cx->runtime->rootITE->next=NULL;
            tmpITE=prevITE=cx->runtime->rootITE;
            continue;            
           }
           cx->runtime->rootITE=tmpITE->next;
           tmpITE=prevITE=cx->runtime->rootITE;
         }else{
           isFirst=0;
           prevITE->next=tmpITE->next;
           tmpITE=tmpITE->next;
         }
          
         free(_tmpITE);
        }else{
         isFirst=0;
         prevITE=tmpITE;
         tmpITE=tmpITE->next;
        }
    }
   #ifdef DEBUG
     printf("GCCalled end\n");
   #endif
 }
 return GCMI._oldCallback?GCMI._oldCallback(cx,theStatus):JS_TRUE;
        
}

JSBool
js_InitITE(JSRuntime *rt){
  InfoTaintEntry *newITE;
 // GlobalObjectWithTainting *newITG;
   GCMI._oldCallback=  JS_SetGCCallbackRT(rt, &markLiveObjects);
 //  rt->tsCollector=NULL;
   newITE=(InfoTaintEntry  *) malloc(  (size_t) sizeof(InfoTaintEntry));
   if(!newITE){
    return JS_FALSE;
   }
   newITE->str=NULL;
   newITE->source=NULL; 
   newITE->refCount=0;
   newITE->op=NONEOP;
   newITE->next=NULL;
   newITE->dep=NULL;
   rt->rootITE=newITE;
   /*
   newITG=(GlobalObjectWithTainting  *) malloc(  (size_t) sizeof(GlobalObjectWithTainting));
   if(!newITG){
    return JS_FALSE;
   }
   newITG->gObj=(JSObject *)-1;
   newITG->next=NULL;
   
    rt->rootITG=newITG;
    */
  return JS_TRUE;  
}

void
js_FinishITE(JSRuntime *rt){
 InfoTaintEntry *tmpITE,*_tmpITE;
// GlobalObjectWithTainting *tmpITG,*_tmpITG;
 JS_SetGCCallbackRT(rt,  GCMI._oldCallback);
 
/* // Free GlobalObjectWithTainting list
 if(tmpITG=rt->rootITG) {
   while(tmpITG=_tmpITG) {
    _tmpITG=tmpITG->next;
    free(tmpITG);
   }
 }
*/
 // Free ITE and ITD lists 
 if(!(tmpITE=rt->rootITE)){
  return;
 }
 if(tmpITE->str==NULL){
  free(tmpITE);
  return ;
 }
 if(tmpITE->dep){
   InfoTaintDep *tmpITD,*_tmpITD;
   _tmpITD=tmpITD=tmpITE->dep->next;
   free(tmpITE->dep);
   while((tmpITD=_tmpITD)) {
     _tmpITD=tmpITD->next;
     if(tmpITD->desc)
       free(tmpITD->desc);
     free(tmpITD);
   }
  }
  _tmpITE=tmpITE;
  while((tmpITE=_tmpITE)) {
     _tmpITE=tmpITE->next;
     free(tmpITE);
  }
}
#if 0
//  // This code is experimental and will cover a different TaintEntry structure.
//  
// void traverseInfoTaintEntry(JSContext *cx ,InfoTaintEntry *ITE,JSObject *obj){
//   InfoTaintEntry *tmpITE;
//   jsval v;
//   JSObject *depArray;
//   
//   v=STRING_TO_JSVAL(ITE->str);
//   JS_SetProperty(cx,obj,"val",&v);
//   if(ITE->source){
//    v=STRING_TO_JSVAL(ITE->source);
//    JS_SetProperty(cx,obj,"source",&v);
//   }
//   v=STRING_TO_JSVAL(JS_NewStringCopyZ(cx,OpNames[(int)ITE->op]));
//   JS_SetProperty(cx,obj,"op",&v);
//   
//   if(ITE->dep && ITE->op <= OpSize ){
//       depArray=JS_NewArrayObject(cx,0,NULL); //JS_DefineObject(cx,obj,"dep",&js_ArrayClass,NULL,0);
//       v=OBJECT_TO_JSVAL(depArray);
//       JS_SetProperty(cx,obj,"dep",&v);
//       traverseInfoTaintDep( cx , ITE->dep,ITE->str, obj,depArray);
//   }
// }
// 
// void traverseInfoTaintDep(JSContext *cx ,InfoTaintDep *ITD,JSString *str,JSObject *obj,JSObject *depArr){
//   InfoTaintDep *tmpITD;
//   InfoTaintEntry *tmpITE;
//   JSObject *entryObj;
//   jsval v;
//   int i;
//   
//   i=0;
//   tmpITD=ITD;
//   while(tmpITD&&tmpITD->entry ){
//    if(tmpITD->entry){
// 
//       
//       entryObj=JS_NewObject(cx,NULL,NULL,NULL);
//      
//       v=INT_TO_JSVAL(tmpITD->spos);
//       JS_SetProperty(cx,entryObj,"startPos",&v);
//      
//       v=INT_TO_JSVAL( tmpITD->epos);
//       JS_SetProperty(cx,entryObj,"endPos",&v);
//       
//       v=OBJECT_TO_JSVAL(entryObj );
//       JS_SetElement(cx,depArr,i,&v);
//      
//       traverseInfoTaintEntry(cx ,tmpITD->entry,entryObj);
//       i++;
//    }
//    tmpITD=tmpITD->next; 
// 
//   }
// }
// #include "jscntxt.h"
// 
// typedef js::RootedValueMap::Range RootRange;
// typedef js::RootedValueMap::Entry RootEntry;
// 
// JSObject *getTaintObject(JSContext *cx){
//     JSRuntime *rt=cx->runtime;
//      /* Warn (but don't assert) debug builds of any remaining roots. */
//     for (RootRange r = rt->gcRootsHash.all(); !r.empty(); r.popFront()) {
//         RootEntry &entry = r.front();
//         if(!strcmp( entry.value.name,TAINTROOT)){
//          return (JSObject *)(entry.key);
//         }
//     }
//     return NULL; 
// 
// }
// /*
//   TE = {val: TaintedStr, op: operationName, parent: window, dep:[TD]}
//   TD = {startPos: concatStartPos, endPos: concatEndPos, desc:}
// 
// */
// JSObject *createTaintedEntry(JSContext *cx,JSString *str,JSString *source, TaintOp op,JSObject *parent,JSObject *dep) {
//   jsval v;
//   JSObject *entryObj=JS_NewObject(cx,NULL,NULL,NULL);
//    v=STRING_TO_JSVAL( str);
//   JS_SetProperty(cx, entryObj,"val",&v);
// 
//   if( source){
//    v=STRING_TO_JSVAL( source);
//    JS_SetProperty(cx,entryObj,"source",&v);
//   }
//   
//   
//   v=STRING_TO_JSVAL(JS_NewStringCopyZ(cx,OpNames[(int)op]));
//   JS_SetProperty(cx,entryObj,"op",&v);
// 
//   if( parent ){
//    v=OBJECT_TO_JSVAL( parent );
//    JS_SetProperty(cx,entryObj,"parent",&v);
//   }
//   
// 
// //   v=OBJECT_TO_JSVAL( dep );
// 
//    // set dependency array
//    JSObject *depArr=JS_NewArrayObject(cx,0,NULL);
//    v=OBJECT_TO_JSVAL( depArr  );
//    JS_SetProperty(cx,entryObj,"dep",&v);
//    if(dep){
//      JS_GetProperty(cx,entryObj,"dep",&v);
//      
//     // array_unshift(cx, 2, Value *vp)
//    }
//   return entryObj;
// }
// 
// 
// JSObject *createTaintedDep(JSContext *cx,JSObject *entry,int spos,int epos,JSObject *desc){
//   jsval v;
//   JSObject *depObj=JS_NewObject(cx,NULL,NULL,NULL);
//   v=INT_TO_JSVAL(spos);
//   JS_SetProperty(cx, depObj,"startPos",&v);
//   
//   v=INT_TO_JSVAL(epos);
//   JS_SetProperty(cx,depObj,"endPos",&v);
//   
//   // TODO
//   v=OBJECT_TO_JSVAL(entry);
//   
//   JS_SetProperty(cx,depObj,"dep",&v);
//   
//   v=OBJECT_TO_JSVAL(desc);
//   JS_SetProperty(cx,depObj,"desc",&v);
//  
//    return depObj ;
// }
// 
// 
// JSObject *findTaintEntry(JSContext *cx,JSString/*o jsval* */ *str){
//   JSObject *tmpTaint= getTaintObject( cx) ;
//   if(!tmpTaint){
//    JSObject *obj=JS_NewArrayObject(cx,0,NULL);
//    
//    JS_SetElement(cx,obj,length,
//    JS_AddNamedObjectRoot(cx,&obj,TAINTROOT);
//    return obj;
//   }
//   do {
//      if(tmpTaint->str==str){
//       return tmpTaint;
//      }
//      tmpTaint=tmpTaint->next;
//   } while(tmpTaint);
//   return NULL; 
// }
// 
// /// TaintInfos
// JSObject *getInfoFromTaintTable(JSContext *cx,JSString *str ){
//   JSObject * obj;
//   InfoTaintEntry *tmpITE;
//   char *name=NULL;                                            
//    JSAtom *atom;
//    JSString *atom_str;
//  
//   atom_str=str;
//   if(!(tmpITE=findTaintEntry(cx, atom_str))){
//    return NULL;
//   }
//   if(tmpITE){
//     //traverseInfoTaintDep(cx , tmpITE->dep);
//     obj=JS_NewObject(cx,NULL,NULL,NULL);
//     traverseInfoTaintEntry(cx , tmpITE, obj);
//   }
//   
//   return  obj;
// }
// 
// // TaintInfo Insert Remove Operations
// InfoTaintEntry *addToTaintTable(JSContext *cx,JSString/*o jsval* */ *str,JSString *source,TaintOp taintop){
//    InfoTaintEntry *newITE,*tmpITE;
//    JSAtom *atom;
//    JSString *atom_str;
//    count++;
// 
//    atom_str=str;
// 
//    if( (tmpITE=findTaintEntry(cx, atom_str)) && tmpITE->op==taintop  ){
//           return tmpITE;
//    }
//    
//    if(!cx->runtime || !cx->runtime->rootITE){
//      return NULL;
//    }
//    if(cx->runtime->rootITE->str==NULL){
//      newITE=cx->runtime->rootITE;
//      newITE->str= atom_str;
//      newITE->source=source;
//      newITE->op=taintop;
//      newITE->dep=NULL;
//    
//    }else{
//      newITE=(InfoTaintEntry  *) JS_malloc(cx, (size_t) sizeof(InfoTaintEntry));
// 
//      if(!newITE){
//       return NULL;
//      }
// 
//      newITE->str=atom_str;
//      newITE->source=source;
//      newITE->op=taintop;
//      newITE->dep=NULL;
// 
//      tmpITE=cx->runtime->rootITE;
//      newITE->next=tmpITE;
//      cx->runtime->rootITE=newITE;
//    }
//    return newITE;
// }
// 
// InfoTaintDep *addToInfoTaintDep(JSContext *cx,InfoTaintEntry *entryDep,InfoTaintDep *next){
//   InfoTaintDep *newITD;
//   
//   newITD=(InfoTaintDep *) JS_malloc(cx, (size_t) sizeof(InfoTaintDep));
//   if(!newITD)
//    return NULL;
//   
//   if(next)
//    newITD->next=next;
//   else
//    newITD->next=NULL;
//   
//   if(entryDep)
//    newITD->entry=entryDep;
//   else
//    newITD->entry=NULL;
//   
//   newITD->spos=-1;
//   newITD->epos=-1;
//   newITD->desc=NULL;
//   return newITD;
// }
// //End TaintInfo Insert Remove
// 
// // Start String Track Taint 
// 
// 
// 
// JSBool 
// addTaintInfoOneArg(JSContext *cx,JSString *argStr,JSString *retStr,char *desc,TaintOp op){
//  InfoTaintEntry *TE,*TTE;
//  InfoTaintDep *TTD;
//  
// 
//  TE=findTaintEntry( cx, argStr);
//  if(!TE){ //if it's not found, maybe we have to create it?
//   return JS_FALSE;
//  }
//  
//  TTE=addToTaintTable( cx, retStr,NULL,op);
//  if(!TTE){
//   return JS_FALSE;
//  }
//  TTD=addToInfoTaintDep(cx,TE,TTE->dep);
//  if(!TTD){
//   return JS_FALSE;
//  }
//  TTD->desc=desc;
//  TTE->dep=TTD;
//  return JS_TRUE;
// }
// 
// JSBool 
// addTaintInfoConcat(JSContext *cx,JSString *argStr,JSString *retStr,int start,int end,TaintOp op){
//  InfoTaintEntry *TE,*TTE;
//  InfoTaintDep *TTD;
// 
//  TE=findTaintEntry( cx, argStr);
//  if(!TE){ //Forse se non lo trova dobbiamo crearlo?
//   return JS_FALSE;
//  }
//  
//  TTE=addToTaintTable( cx, retStr,NULL,op);
//  if(!TTE){
//   return JS_FALSE;
//  }
// 
//  TTD=addToInfoTaintDep(cx,TE,TTE->dep);
//  if(!TTD){
//   return JS_FALSE;
//  }
//  TTD->spos=start;
//  TTD->epos=end;
//  
//  TTD->desc=NULL;
//  TTE->dep=TTD;
//  
//  return JS_TRUE; 
// }
//  
// //String Track Taint 
// static struct GCManagerInfo{
//   JSGCCallback _oldCallback;
// } GCMI;
// 
// static JSBool markLiveObjects(JSContext *cx, JSGCStatus theStatus){
//  InfoTaintEntry *tmpITE ,*prevITE;
//  int isFirst=1;
//  JSBool last;
// // JSClass *clasp;
//  if (JSGC_MARK_END!=theStatus){
//      return JS_TRUE;
//  }
//  JSTracer *trc= cx->runtime->gcMarkingTracer;
//  printf("GCCalled\n");
//   tmpITE= cx->runtime->rootITE;
//   prevITE= cx->runtime->rootITE;
//   if(trc)
//   while(tmpITE) {
//      
//         if (tmpITE->source && JS_IsAboutToBeFinalized(cx, tmpITE->source )) {
//               js::gc::MarkGCThing(trc, (tmpITE->source) , "Taint Info" );
//        }
//         
//         if ( tmpITE->str && JS_IsAboutToBeFinalized(cx, tmpITE->str  )) {
// //           if(cx->globalObject) {
//  //            clasp = OBJ_GET_CLASS(cx,  cx->globalObject);
// //           }
//             js::gc::MarkGCThing(trc,  tmpITE->str, "Taint Info" );
//         }
//         prevITE=tmpITE;
//         isFirst=0;
//         tmpITE=tmpITE->next;
//     }
//  printf("GCCalled end\n");
//     
//  return GCMI._oldCallback?GCMI._oldCallback(cx,theStatus):JS_TRUE;
//         
// }
// 
// JSBool
// js_InitITE(JSRuntime *rt){
//   InfoTaintEntry *newITE;
//    
//    
//  // GCMI._oldCallback=  JS_SetGCCallbackRT(rt, &markLiveObjects);
//    newITE=(InfoTaintEntry  *) malloc(  (size_t) sizeof(InfoTaintEntry));
//    if(!newITE){
//     return JS_FALSE;
//    }
//    newITE->str=NULL;
//    newITE->source=NULL;
//    newITE->op=NONEOP;
//    newITE->next=NULL;
//    newITE->dep=NULL;
//    rt->rootITE=newITE;
//   return JS_TRUE;  
// }
// 
// void
// js_FinishITE(JSRuntime *rt){
//  InfoTaintEntry *tmpITE,*_tmpITE;
//  //JS_SetGCCallbackRT(rt,  GCMI._oldCallback);
//  if(!(tmpITE=rt->rootITE)){
//   return;
//  }
//  if(tmpITE->str==NULL){
//   free(tmpITE);
//   return ;
//  }
//  if(tmpITE->dep){
//    InfoTaintDep *tmpITD,*_tmpITD;
//    _tmpITD=tmpITD=tmpITE->dep->next;
//    free(tmpITE->dep);
//    while((tmpITD=_tmpITD)) {
//      _tmpITD=tmpITD->next;
//      if(tmpITD->desc)
//        free(tmpITD->desc);
//      free(tmpITD);
//    }
//   }
//   _tmpITE=tmpITE;
//   while((tmpITE=_tmpITE)) {
//      _tmpITE=tmpITE->next;
//      free(tmpITE);
//   }
// }
#endif /* #if 0*/

JSBool
taint_getTaintInfo(JSContext *cx, uintN argc, jsval *vp)
{
    jsval *argv;
    jschar *chars;
    uintN i;
    size_t len;
    uint16 code;
    JSString *str,*str1,*astr;
    JSObject *obj;
    
    //XXXStefano Note: is this the correct one?
    // Trying to prevent some race condition on GC
    //js::AutoLockGC lock(cx->runtime);

    argv = vp + 2;
    JS_ASSERT(argc < js::StackSpace::ARGS_LENGTH_MAX);
    // Set "" if JSVAL IS NULL or argc ==0
    if(JSVAL_IS_STRING(argv[0])){
     str = JSVAL_TO_STRING(argv[0]);
     obj=getInfoFromTaintTable(cx,str);
     
     //js_NewString();
     //     printVal(cx,astr);   
     *vp = OBJECT_TO_JSVAL(obj); 
    
     return JS_TRUE;
    }
    return JS_FALSE;
}

JSBool
taint_getAllTaintInfo(JSContext *cx, uintN argc, jsval *vp)
{
    JSObject *obj;

    InfoTaintEntry *tmpITE; 
    tmpITE=cx->runtime->rootITE;
    while(tmpITE){
     obj=getInfoFromTaintTable(cx,tmpITE->str );
     
     tmpITE=tmpITE->next;
     
    }
    *vp = OBJECT_TO_JSVAL(obj); 
    return JS_TRUE;
}



////



JSBool taint_GetTainted(JSContext *cx,JSString *str,jsval *v){
  *v=BOOLEAN_TO_JSVAL(str->isTainted()?JS_TRUE:JS_FALSE);
  return JS_TRUE;
}

JSBool taint_deTaint(JSContext *cx, uintN argc, jsval *vp){
    jsval *argv;
    const jschar *chars;
   size_t len;
    JSString *str1,*astr;
    argv = vp + 2;
     if(JSVAL_IS_STRING(argv[0])){
     str1= JSVAL_TO_STRING(argv[0]);
     if(JSSTRING_IS_TAINTED(str1)){
         //str1->getCharsAndLength(chars,len);
         chars=str1->getChars(cx);
         len= str1->length();
         astr=js_NewStringCopyN(cx,chars,len);
         if (!astr) {
             return JS_FALSE;
         } 
     *vp = STRING_TO_JSVAL(astr);
     return JS_TRUE;    
     } else{
       *vp = argv[0];
       return JS_TRUE;
 }
 }
   *vp = argv[0];
       return JS_TRUE;
}


JSBool taint_newTainted(JSContext *cx, uintN argc, jsval *vp)
{
    jsval *argv;
    const jschar *chars;
    size_t len;
    JSString *str1,*astr;
    
    //XXXStefano Note: is this the correct one?
    // Trying to prevent some race condition on GC
     //js::AutoLockGC lock(cx->runtime);

    argv = vp + 2;
    JS_ASSERT(argc  <=  js::StackSpace::ARGS_LENGTH_MAX);
    // Set "" if JSVAL IS NULL or argc ==0

    if(JSVAL_IS_STRING(argv[0])){
     str1= JSVAL_TO_STRING(argv[0]);
     if(!JSSTRING_IS_TAINTED(str1)){
        // str1->getCharsAndLength(chars,len);
         chars=str1->getChars(cx);
         len= str1->length();

         astr=js_NewStringCopyN(cx,chars,len);
         if (!astr) {
           //  cx->free(chars);
             return JS_FALSE;
         }
         JSSTRING_SET_TAINTED(astr);
     }else{
       astr=str1;
     }
    if(!JSVAL_IS_NULL(argv[1]) && JSVAL_IS_STRING(argv[1])){
      JSString *bindStr;
      bindStr=  JSVAL_TO_STRING(argv[1]);

      addToTaintTable(cx,astr,bindStr,SOURCE);
       
    }else{
          JSString *bindStr;
      bindStr= cx->runtime->emptyString;
      addToTaintTable(cx,astr,bindStr,SOURCE);
   
    }

   //  JS_AddNamedStringRoot(cx,&astr,"Taint");
     *vp = STRING_TO_JSVAL(astr);    
    return JS_TRUE;
    }
    return JS_FALSE;
}

// TODO: implement for taint propagation and operation flow.
// String.newTaintDependence(newTaintedString,OriginalString,[args?]|[OPERATIONNAME])
JSBool taint_newTaintedDependence(JSContext *cx, uintN argc, jsval *vp)
{
    jsval *argv;
    const jschar *chars;
    size_t len;
    JSString *str1,*astr;
    //XXXStefano Note: is this the correct one?
    // Trying to prevent some race condition on GC
    js::AutoLockGC lock(cx->runtime);
 /*   argv = vp + 2;
    JS_ASSERT(argc  <= JS_ARGS_LENGTH_MAX);
    // Set "" if JSVAL IS NULL or argc ==0

    if(JSVAL_IS_STRING(argv[0])){
     str1= JSVAL_TO_STRING(argv[0]);
     if(!JSSTRING_IS_TAINTED(str1)){
        // str1->getCharsAndLength(chars,len);
         chars=str1->getChars(cx);
         len= str1->length();

         astr=js_NewStringCopyN(cx,chars,len);
         if (!astr) {
           //  cx->free(chars);
             return JS_FALSE;
         }
         JSSTRING_SET_TAINTED(astr);
     }else{
       astr=str1;
     }
    if(!JSVAL_IS_NULL(argv[1]) && JSVAL_IS_STRING(argv[1])){
      JSString *bindStr;
      bindStr=  JSVAL_TO_STRING(argv[1]);

      addToTaintTable(cx,astr,bindStr,SOURCE);
       
    }else{
          JSString *bindStr;
      bindStr= cx->runtime->emptyString;
      addToTaintTable(cx,astr,bindStr,SOURCE);
   
    }

     *vp = STRING_TO_JSVAL(astr);    
    return JS_TRUE;
    }*/
    return JS_FALSE; 
}
JSString *
taint_newTaintedString(JSContext *cx, JSString *oriStr)
{
 
    const jschar *chars; 
    size_t len; 
    JSString *str,*str1,*astr;
     
    //XXXStefano Note: is this the correct one?
    // Trying to prevent some race condition on GC
    js::AutoLockGC lock(cx->runtime);

    str1= oriStr;
       //  str1->getCharsAndLength(const_cast<const jschar *&> (chars),len);
    chars= str1->getChars(cx);
    len= str1->length();
    astr=js_NewStringCopyN(cx,chars,len);
    if (!astr) {
        //JS_free(cx, chars);
        return JS_FALSE;
    }
    JSSTRING_SET_TAINTED(astr);
    //JS_AddNamedStringRoot(cx,&astr,"Taint");
    return  astr;
}
 
void logTaint(JSContext *cx ,const  char *what,const  char *who,jsval *argv){
       JSObject *jobj,*gobj ,*funargs;
       jsval _rval,_arg[4], domiObj ,domiUtil, domiUi,_rvalArgs;
       void *mark;
       JSBool ok;
       gobj= JS_GetGlobalObject(cx);
       if(cx && cx->fp() && cx->fp()->script() ){
        
        const char *c=cx->fp()->script()->filename;
        if(c[0]=='c' && c[1]=='h' && c[2]=='r' && c[3]=='o' && c[4]=='m' ){
            return;
          }
       }
       // get ___domIntruderObj
       if (!JS_GetProperty(cx,  gobj, DOMINATOROBJ ,  &domiObj)){
   #ifdef DEBUG
        printf("Error JS_GetProperty !!\n");
   #endif
       }
       if(!JSVAL_IS_VOID(domiObj )){
       if (!JS_GetProperty(cx, JSVAL_TO_OBJECT( domiObj), DOMINATORLOG ,  &domiUtil)){
         #ifdef DEBUG
         printf("Error JS_GetProperty !!\n");
         #endif
        
       }
       if( cx->fp()->isFunctionFrame() && cx->fp()->fun() && 
         (!((cx->fp()->fun()->flags) & JSFUN_HEAVYWEIGHT) || 
           (JSObject *)&(cx->fp()->varObj())!= NULL))
            funargs=js_GetArgsObject(cx, cx->fp());
       else{
            funargs=NULL;
       }
       //  _arg = JS_PushArguments(cx, &mark, "ssSo",what,who ,js_ValueToString( cx,  argv[0]) , funargs );
         _arg[0]= STRING_TO_JSVAL(JS_NewStringCopyZ(cx,what ));
         _arg[1]=STRING_TO_JSVAL(JS_NewStringCopyZ(cx, who ) );
         _arg[2]=  argv[0] ;
         _arg[3]= OBJECT_TO_JSVAL( funargs ) ;
         
        if(!JS_CallFunctionValue(cx,  JSVAL_TO_OBJECT( domiObj)  , domiUtil , 4, _arg, &_rvalArgs)){
          #ifdef DEBUG
                 printf("Error domiUtil\n");
          #endif
        }
       // JS_PopArguments(cx, mark);
      //  printf("FINE domiUtil!!\n");
        }else{
         //printf("ERROR :what %s %s %s\n",what,who,js_GetStringBytes(cx,js_ValueToString( cx,  argv[0]))); 
        }
}

void EvalLog(JSContext *cx,jsval *argv) {
   if( JSSTRING_IS_TAINTED(JSVAL_TO_STRING(argv[0]))){
       logTaint(cx, "Sink" , "eval", argv);
   }
}

//---
 
JSBool js_ObjectHasKeyTainted(JSContext *cx,JSObject *obj){
  // JSScope *scope;
   JSIdArray *ida;
   jsuint i,length;
   jschar *chars, *ochars, *vsharp;
   JSString *idstr, *valstr, *str;
   jsval *val, val2;
   jsid id2;
   jsuint   slots;
   
   JS_CHECK_RECURSION(cx, return JS_FALSE);

   ida=JS_Enumerate(cx, obj);
   for (i = 0, length = ida->length; i < length; i++) {// check Key Taitned on Normal Object
      id2 = ida->vector[i];
      if(JSID_IS_ATOM(id2) && js::IdToValue(id2).isString() ){
        idstr = js::IdToValue(id2).toString();
        if(idstr->isTainted()){
          return JS_TRUE;
        }
      }
    }
    if (obj->isDenseArray()) { // check Key Taitned on DENSE ARRAY
        slots = JS_MIN(obj->getArrayLength(), obj->getDenseArrayCapacity());
                       
        for (i = 0; i < slots; i++) {
         //   val2 = obj->dslots[i];
             val2= Jsvalify(obj->getDenseArrayElement(i));
            if ( JSVAL_IS_STRING(val2) && JSSTRING_IS_TAINTED(JSVAL_TO_STRING(val2))){
                return JS_TRUE;
             }
        }

        return JS_FALSE;
    }
    
#if 0    
    // Check Tainted Values.. We don't know if it's ok to get this too.
    scope=OBJ_SCOPE(obj );
    slots = STOBJ_NSLOTS(obj);
    if ( scope->owned() && scope->freeslot <  slots)
      slots = scope->freeslot;
      
      i = JSSLOT_PRIVATE;
    if ( (STOBJ_GET_CLASS(obj))->flags & JSCLASS_HAS_PRIVATE) {
        i = JSSLOT_PRIVATE + 1;

    }
        for (; i < slots; i++) {
        val2 = STOBJ_GET_SLOT(obj, i);
         
        if (JSVAL_IS_STRING(val2) && JSSTRING_IS_TAINTED(JSVAL_TO_STRING(val2))) {

           return 2;
        }
      
    }
#endif
    return JS_FALSE;
 
}
 
/*
// -- taintConcat--

JSBool taint_setTaintConcatN(JSContext *cx,jsval *sp,int argc,JSString **resStr){
 jsval *vr,*vl;
 vr=  sp - argc;
 vl=vr++;
 JSString *leftStr,*rightStr ;
 if(!(leftStr=js_ValueToString(cx,*vl)) || !(rightStr=js_ValueToString(cx,*vr))){
   return JS_FALSE;
 }
 *resStr=js_ConcatStrings(cx,leftStr,rightStr);
 for(vr++;vr < sp;vr++){
   if(!(rightStr=js_ValueToString(cx,*vr))){
    return JS_FALSE;
   }
   *resStr=js_ConcatStrings(cx,*resStr,rightStr);
 }
 return JS_TRUE;
}
*/
#endif
