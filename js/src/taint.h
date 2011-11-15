#ifndef jsstr_h___
#include "jsstr.h"
#endif
#ifndef taint_h___
#define taint_h___
#ifdef TAINTED
/*
typedef struct Tainted{
  JSString *str;
  struct Tainted *next;
} Tainted;
*/
//#define JSSTRING_IS_TAINTED(cx,str) isTainted(cx,str)
//#define JSSTRING_SET_TAINTED(cx,str) setTainted(cx,str,JS_TRUE)
#define js_GetStringBytes(cx,str) JS_EncodeString(cx,str)
#define  JSSTRING_IS_TAINTED(str) (str)->isTainted()
#define JSSTRING_SET_TAINTED(str) (str)->setTainted()
// #define  JSSTRING_CHARS_AND_LENGTH(str,chars,len)  (str)->getCharsAndLength((chars),(len))

#define  TAINT_CONDITION(str) \
    JSBool tainted=JS_FALSE;\
    JSString *strArg;\
    if(str->isTainted()){\
      tainted=JS_TRUE;\
       strArg=str; \
    }
#define  TAINT_CONDITION_NODEC(str) \
    if(str->isTainted()){\
      tainted=JS_TRUE;\
       strArg=str; \
    }

// Remember to add history (taintInfoArg)
#define  TAINT_COND_SET(sub,argStr,desc,op)        \
        if(tainted){\
          if(sub->length()<10)\
           sub=taint_newTaintedString(cx,sub);\
          sub->setTainted();\
          addTaintInfoOneArg(cx,argStr,sub,desc,op);\
        }

#define  TAINT_COND_SET_NO_ARG(sub)        \
        if(tainted){\
          sub->setTainted();\
        }
        
#define  TAINT_COND_SET_NEW(sub,argStr,desc,op)        \
        if(tainted){\
          sub=taint_newTaintedString(cx,sub);\
          sub->setTainted();\
          addTaintInfoOneArg(cx,argStr,sub,desc,op);\
        }

#define DEFINE_NEWTAINT() \
 static JSBool str_newTainted(JSContext *cx, uintN argc, jsval *vp){\
   return taint_newTainted(cx,argc,vp);\
 } \
 static JSBool str_unTaint(JSContext *cx, uintN argc, jsval *vp){\
   return taint_deTaint(cx,argc,vp);\
 }  
 
#ifndef TAINTSTRUCTS

#define TAINTSTRUCTS
//remember this is duplicated in jscntxt.h 
// any change here must be replicated there
// also OpNames must be added in taint.cpp
typedef enum taintop {NONEOP,GET,SET,SOURCE,SINK,SUBSTRING,LOWERCASE,UPPERCASE,JOIN,SPLIT,SLICE,REPLACE,REGEXP,CONCAT,CONCATLEFT,CONCATRIGHT,ESCAPE,UNESCAPE,ENCODEURI,UNENCODEURI,ENCODEURICOMPONENT,UNENCODEURICOMPONENT,TRIM,TAGIFY,QUOTE,DEPEND,ATOB,BTOA} TaintOp;

typedef struct InfoTaintEntry{
 JSString *str;
 TaintOp  op;
 JSString *source;
 struct InfoTaintDep *dep;
 struct InfoTaintEntry *next;
} InfoTaintEntry;

typedef struct InfoTaintDep{
 InfoTaintEntry *entry;
 int spos;
 int epos;
 char *desc;
 struct InfoTaintDep *next;
} InfoTaintDep;
#endif /*IfNotDef TAINTSTRUCTS*/
 
#define DEFINE_GETTAINTINFO() \
 static JSBool str_getTaintInfo(JSContext *cx, uintN argc, jsval *vp){\
   return taint_getTaintInfo(cx,argc,vp);\
 } \
 static JSBool  str_getAllTaintInfo(JSContext *cx, uintN argc, jsval *vp){\
   return taint_getAllTaintInfo(cx,argc,vp);\
 }  

#define SET_NEWTAINTED() JS_FN("newTainted",    str_newTainted,       2,0),\
    JS_FN("unTaint",    str_unTaint,       1,0),\
    JS_FN("getTaintInfo",    str_getTaintInfo,       1,0),\
    JS_FN("getAllTaintInfo",    str_getAllTaintInfo,       0,0),

//#define JSSTRING_UNSET_TAINTED(cx,str) setTainted(cx,str,JS_FALSE)

//extern Tainted *findTainted(JSContext *cx,JSString *str);
extern JSBool isTainted(JSContext *cx,JSString *str);
extern JSBool setTainted(JSContext *cx,JSString *str,JSBool aTaint);
extern void EvalLog(JSContext *cx,jsval *vp);
extern void logTaint(JSContext *cx ,const char *what,const char *who,jsval *argv);

extern JSBool 
addTaintInfoOneArg(JSContext *cx,JSString *argStr,JSString *retStr,char *desc,TaintOp op);

extern JSBool 
addTaintInfoConcat(JSContext *cx,JSString *argStr,JSString *retStr,int start,int end,TaintOp op);

extern InfoTaintEntry *findTaintEntry(JSContext *cx,JSString  *str);
extern InfoTaintDep *addToInfoTaintDep(JSContext *cx,InfoTaintEntry *entryDep,InfoTaintDep *next);
extern InfoTaintEntry *addToTaintTable(JSContext *cx,JSString *str,JSString *source,TaintOp taintop);

extern JSString *taint_newTaintedString(JSContext *cx, JSString *str);
extern JSBool taint_newTainted(JSContext *cx, uintN argc, jsval *vp);
extern JSBool taint_deTaint(JSContext *cx, uintN argc, jsval *vp);
extern JSBool taint_GetTainted(JSContext *cx, JSString *str, jsval *vp);
extern JSBool taint_getTaintInfo(JSContext *cx, uintN argc, jsval *vp);
extern JSBool taint_getAllTaintInfo(JSContext *cx, uintN argc, jsval *vp);

extern JSBool taint_setTaintConcatN(JSContext *cx,jsval *sp,int argc,JSString **resStr);
extern JSBool js_ObjectHasKeyTainted(JSContext *cx,JSObject *obj);
extern JSBool
js_InitITE(JSRuntime *rt);
extern void
js_FinishITE(JSRuntime *rt);

#endif
#endif
