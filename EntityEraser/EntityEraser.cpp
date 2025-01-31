// EntityEraser.cpp : 定义 DLL 的导出函数。
//

#include "pch.h"
#include "framework.h"
#include "EntityEraser.h"
using namespace std;
JNIEXPORT jint JNICALL Java_apphhzp_lib_natives_NativeUtil_postMsg(JNIEnv* env, jclass obj, jlong hWnd, jint msg, jlong wParam, jlong lParam) {
	return PostMessage((HWND)hWnd, msg, wParam, lParam);
}
JNIEXPORT jlong JNICALL Java_apphhzp_lib_natives_NativeUtil_getActiveWindow(JNIEnv* env, jclass obj) {
	return (jlong)GetActiveWindow();
}

//BYTE OldCode[12] = { 0x00 };
//BYTE HookCode[12] = { 0x48, 0xB8, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0xFF, 0xE0 };
//
//void HookFunction64(LPCWSTR lpModule, LPCSTR lpFuncName, LPVOID lpFunction)
//{
//    DWORD_PTR FuncAddress = (UINT64)GetProcAddress(GetModuleHandle(lpModule), lpFuncName);
//    DWORD OldProtect = 0;
//
//    if (VirtualProtect((LPVOID)FuncAddress, 12, PAGE_EXECUTE_READWRITE, &OldProtect))
//    {
//        memcpy(OldCode, (LPVOID)FuncAddress, 12);                   // 拷贝原始机器码指令
//        *(PINT64)(HookCode + 2) = (UINT64)lpFunction;               // 填充90为指定跳转地址
//    }
//    memcpy((LPVOID)FuncAddress, &HookCode, sizeof(HookCode));       // 拷贝Hook机器指令
//    VirtualProtect((LPVOID)FuncAddress, 12, OldProtect, &OldProtect);
//}
//void UnHookFunction64(LPCWSTR lpModule, LPCSTR lpFuncName)
//{
//    DWORD OldProtect = 0;
//    UINT64 FuncAddress = (UINT64)GetProcAddress(GetModuleHandle(lpModule), lpFuncName);
//    if (VirtualProtect((LPVOID)FuncAddress, 12, PAGE_EXECUTE_READWRITE, &OldProtect))
//    {
//        memcpy((LPVOID)FuncAddress, OldCode, sizeof(OldCode));
//    }
//    VirtualProtect((LPVOID)FuncAddress, 12, OldProtect, &OldProtect);
//}

//int WINAPI MyMessageBoxW(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType)
//{
//    UnHookFunction64(L"user32.dll", "MessageBoxW");
//    int ret = MessageBoxW(0, L"hello lyshark", lpCaption, uType);
//    HookFunction64(L"user32.dll", "MessageBoxW", (PROC)MyMessageBoxW);
//    return ret;
//}
JNIEXPORT void JNICALL Java_apphhzp_lib_natives_NativeUtil_createMsgBox(JNIEnv* env, jclass obj, jstring text, jstring title, jint flags) {
    //HookFunction64(L"user32.dll", "MessageBoxW", (PROC)MyMessageBoxW);
	const jchar *a = env->GetStringChars(text, NULL), *b = env->GetStringChars(title, NULL);
	MessageBox(NULL, a, b, flags);
	env->ReleaseStringChars(text, a);
	env->ReleaseStringChars(title, b);
}
//===================================================Agent Start===================================================
JPLISInitializationError createNewJPLISAgent_(JavaVM * vm, JPLISAgent **agent_ptr);
void convertCapabilityAttributes(JPLISAgent* agent);
JNIEXPORT jobject JNICALL Java_apphhzp_lib_natives_NativeUtil_createInstrumentationImpl(JNIEnv* env, jclass obj) {
    JavaVM* vm;
    env->GetJavaVM(&vm);
    if (vm == NULL) {
        MessageBox(NULL, L"Couldn't get JavaVM!", L"ApphhzpLIB.dll ERR", MB_OK | MB_ICONERROR);
        return NULL;
    }
    _JPLISAgent* agent = NULL;
    JPLISInitializationError err = createNewJPLISAgent_(vm, &agent);
    if (agent == NULL || err != JPLIS_INIT_ERROR_NONE) {
        MessageBox(NULL, L"Couldn't create _JPLISAgent!", L"ApphhzpLIB.dll ERR", MB_OK | MB_ICONERROR);
        return NULL;
    }
    jclass implClass = env->FindClass("sun/instrument/InstrumentationImpl");
    agent->mTransform = env->GetMethodID(implClass, "transform", "(Ljava/lang/Module;Ljava/lang/ClassLoader;Ljava/lang/String;Ljava/lang/Class;Ljava/security/ProtectionDomain;[BZ)[B");
    jobject localReference = NULL;
    localReference = env->NewObject(
        implClass,
        env->GetMethodID(implClass,
            "<init>",
            "(JZZ)V"),
        (jlong)agent,
        agent->mRedefineAdded,
        agent->mNativeMethodPrefixAdded);
    if (localReference == NULL) {
        MessageBox(NULL, L"Couldn't create localReference for InstrumentationImpl!", L"ApphhzpLIB.dll ERR", MB_OK | MB_ICONERROR);
        return NULL;
    }
    jobject re = NULL;
    re = env->NewGlobalRef(localReference);
    agent->mInstrumentationImpl = re;
    convertCapabilityAttributes(agent);
    return re;
}
void checkCapabilities(JPLISAgent * agent) {
    jvmtiEnv *          jvmtienv = jvmti(agent);
    jvmtiCapabilities   potentialCapabilities;
    jvmtiError          jvmtierror;
    memset(&potentialCapabilities, 0, sizeof(potentialCapabilities));
    jvmtierror = jvmtienv->GetPotentialCapabilities(&potentialCapabilities);
    if (jvmtierror == JVMTI_ERROR_NONE ) {
        if (potentialCapabilities.can_redefine_classes==1) {
            agent->mRedefineAvailable = 1;
        }
        if (potentialCapabilities.can_set_native_method_prefix==1) {
            agent->mNativeMethodPrefixAvailable = 1;
        }
    }
}
void* allocate(jvmtiEnv* jvmtienv, size_t bytecount) {
    void* resultBuffer = NULL;
    jvmtiError error = JVMTI_ERROR_NONE;
    error = jvmtienv->Allocate(bytecount, (unsigned char**)&resultBuffer);
    if (error != JVMTI_ERROR_NONE) {
        resultBuffer = NULL;
    }
    return resultBuffer;
}
void deallocate(jvmtiEnv * jvmtienv, void * buffer) {
    jvmtienv->Deallocate((unsigned char*)buffer);
}
JPLISAgent *allocateJPLISAgent(jvmtiEnv * jvmtienv) {
    return (JPLISAgent *) allocate(jvmtienv,sizeof(JPLISAgent));
}
void addRedefineClassesCapability(JPLISAgent * agent) {
    jvmtiEnv *          jvmtienv = jvmti(agent);
    jvmtiCapabilities   desiredCapabilities;
    jvmtiError          jvmtierror;
    if (agent->mRedefineAvailable && !agent->mRedefineAdded) {
        jvmtierror = (jvmtienv)->GetCapabilities(&desiredCapabilities);
        desiredCapabilities.can_redefine_classes = 1;
        jvmtierror = (jvmtienv)->AddCapabilities(&desiredCapabilities);
        if (jvmtierror==JVMTI_ERROR_NONE) {
            agent->mRedefineAdded=1;
        }
    }
}
JPLISEnvironment* getJPLISEnvironment(jvmtiEnv* jvmtienv) {
    JPLISEnvironment* environment = NULL;
    jvmtiError         jvmtierror = JVMTI_ERROR_NONE;
    jvmtierror = jvmtienv->GetEnvironmentLocalStorage((void**)&environment);
    if (jvmtierror != JVMTI_ERROR_NONE) {
        environment = NULL;
    }
    return environment;
}
jthrowable preserveThrowable(JNIEnv * jnienv) {
    jthrowable result = jnienv->ExceptionOccurred();
    if (result != NULL ) {
        jnienv->ExceptionClear();
    }
    return result;
}
void throwThrowable(JNIEnv* jnienv,jthrowable exception) {
    if (exception != NULL) {
        jint result=jnienv->Throw(exception);
    }
}
void restoreThrowable(JNIEnv* jnienv,jthrowable  preservedException) {
    throwThrowable(jnienv,preservedException);
}
#define JPLIS_CURRENTLY_INSIDE_TOKEN                ((void *) 0x7EFFC0BB)
#define JPLIS_CURRENTLY_OUTSIDE_TOKEN               ((void *) 0)
jvmtiError confirmingTLSSet(   jvmtiEnv *      jvmtienv,
    jthread         thread,
    const void *    newValue) {
    jvmtiError  error;
    error = jvmtienv->SetThreadLocalStorage(thread,newValue);
    check_phase_ret_blob(error, error);

    return error;
}
void assertTLSValue( jvmtiEnv *      jvmtienv,
    jthread         thread,
    const void *    expected) {
    jvmtiError  error;
    void *      test=(void *)0x99999999ULL;
    error = (jvmtienv)->GetThreadLocalStorage(thread,&test);
    check_phase_ret(error);
}
jboolean tryToAcquireReentrancyToken(jvmtiEnv* jvmtienv, jthread thread) {
    jboolean    result = 0;
    jvmtiError  error = JVMTI_ERROR_NONE;
    void* storedValue = NULL;
    error = jvmtienv->GetThreadLocalStorage(thread, &storedValue);
    check_phase_ret_false(error);
    if (error == JVMTI_ERROR_NONE) {
        /* if this thread is already inside, just return false and short-circuit */
        if (storedValue == JPLIS_CURRENTLY_INSIDE_TOKEN) {
            result = 0;
        } else {
            error = confirmingTLSSet(jvmtienv,thread,JPLIS_CURRENTLY_INSIDE_TOKEN);
            check_phase_ret_false(error);
            if (error != JVMTI_ERROR_NONE) {
                result = 0;
            } else {
                result = 1;
            }
        }
    }
    return result;
}
jboolean checkForAndClearThrowable(JNIEnv* jnienv) {
    jboolean result = jnienv->ExceptionCheck();
    if (result){
        jnienv->ExceptionClear();
    }
    return result;
}
void releaseReentrancyToken(jvmtiEnv* jvmtienv, jthread thread) {
    confirmingTLSSet(jvmtienv, thread, JPLIS_CURRENTLY_OUTSIDE_TOKEN);
}
static jobject getModuleObject(jvmtiEnv*               jvmti,
    jobject                 loaderObject,
    const char*             cname) {
    jvmtiError err = JVMTI_ERROR_NONE;
    jobject moduleObject = NULL;
    const char* last_slash = ((cname == NULL) ? NULL : strrchr(cname, '/'));
    int len = (last_slash == NULL) ? 0 : (int)(last_slash - cname);
    char* pkg_name_buf = (char*)malloc(len + 1);
    if (pkg_name_buf == NULL) {
        fprintf(stderr, "OOM error in native tmp buffer allocation");
        return NULL;
    }
    if (last_slash != NULL) {
        strncpy(pkg_name_buf, cname, len);
    }
    pkg_name_buf[len]='\0';
    err=(jvmti)->GetNamedModule(loaderObject, pkg_name_buf, &moduleObject);
    free((void*)pkg_name_buf);
    check_phase_ret_blob(err, NULL);
    return moduleObject;
}
void transformClassFile(             JPLISAgent *            agent,
    JNIEnv *                jnienv,
    jobject                 loaderObject,
    const char*             name,
    jclass                  classBeingRedefined,
    jobject                 protectionDomain,
    jint                    class_data_len,
    const unsigned char*    class_data,
    jint*                   new_class_data_len,
    unsigned char**         new_class_data,
    jboolean                is_retransformer) {
    jboolean        errorOutstanding        = JNI_FALSE;
    jstring         classNameStringObject   = NULL;
    jarray          classFileBufferObject   = NULL;
    jarray          transformedBufferObject = NULL;
    jsize           transformedBufferSize   = 0;
    unsigned char * resultBuffer            = NULL;
    jboolean        shouldRun               = JNI_FALSE;
    /* only do this if we aren't already in the middle of processing a class on this thread */
    shouldRun = tryToAcquireReentrancyToken(jvmti(agent),NULL);  /* this thread */
    if ( shouldRun ) {
        /* first marshall all the parameters */
        classNameStringObject = (jnienv)->NewStringUTF(name);
        errorOutstanding = checkForAndClearThrowable(jnienv);

        if ( !errorOutstanding ) {
            classFileBufferObject = (jnienv)->NewByteArray(class_data_len);
            errorOutstanding = checkForAndClearThrowable(jnienv);
        }
        if ( !errorOutstanding ) {
            jbyte * typedBuffer = (jbyte *) class_data; /* nasty cast, dumb JNI interface, const missing */
            /* The sign cast is safe. The const cast is dumb. */
            (jnienv)->SetByteArrayRegion(
                (jbyteArray)classFileBufferObject,
                0,
                class_data_len,
                typedBuffer);
            errorOutstanding = checkForAndClearThrowable(jnienv);
        }

        /*  now call the JPL agents to do the transforming */
        /*  potential future optimization: may want to skip this if there are none */
        if ( !errorOutstanding ) {
            jobject moduleObject = NULL;

            if (classBeingRedefined == NULL) {
                moduleObject = getModuleObject(jvmti(agent), loaderObject, name);
            } else {
                // Redefine or retransform, InstrumentationImpl.transform() will use
                // classBeingRedefined.getModule() to get the module.
            }
            transformedBufferObject=(jbyteArray)(jnienv)->CallObjectMethod(
                agent->mInstrumentationImpl,
                agent->mTransform,
                moduleObject,
                loaderObject,
                classNameStringObject,
                classBeingRedefined,
                protectionDomain,
                classFileBufferObject,
                is_retransformer);
            errorOutstanding = checkForAndClearThrowable(jnienv);
        }

        /* Finally, unmarshall the parameters (if someone touched the buffer, tell the JVM) */
        if ( !errorOutstanding ) {
            if ( transformedBufferObject != NULL ) {
                transformedBufferSize = jnienv->GetArrayLength(transformedBufferObject);
                errorOutstanding = checkForAndClearThrowable(jnienv);
                if ( !errorOutstanding ) {
                    /* allocate the response buffer with the JVMTI allocate call.
                    *  This is what the JVMTI spec says to do for Class File Load hook responses
                    */
                    jvmtiError  allocError = jvmti(agent)->Allocate(transformedBufferSize,&resultBuffer);
                    errorOutstanding = (allocError != JVMTI_ERROR_NONE);
                }

                if ( !errorOutstanding ) {
                    (jnienv)->GetByteArrayRegion((jbyteArray)transformedBufferObject,
                        0,
                        transformedBufferSize,
                        (jbyte *) resultBuffer);
                    errorOutstanding = checkForAndClearThrowable(jnienv);
                    if ( errorOutstanding ) {
                        deallocate( jvmti(agent),
                            (void*)resultBuffer);
                    }
                }
                if ( !errorOutstanding ) {
                    *new_class_data_len = (transformedBufferSize);
                    *new_class_data     = resultBuffer;
                }
            }
        }
        releaseReentrancyToken( jvmti(agent),NULL);

    }

    return;
}
void JNICALL eventHandlerClassFileLoadHook(jvmtiEnv* jvmtienv,
    JNIEnv* jnienv,
    jclass                  class_being_redefined,
    jobject                 loader,
    const char* name,
    jobject                 protectionDomain,
    jint                    class_data_len,
    const unsigned char* class_data,
    jint* new_class_data_len,
    unsigned char** new_class_data) {
    JPLISEnvironment* environment = NULL;
    environment = getJPLISEnvironment(jvmtienv);
    if (environment != NULL) {
        jthrowable outstandingException = preserveThrowable(jnienv);
        transformClassFile(environment->mAgent,
            jnienv,
            loader,
            name,
            class_being_redefined,
            protectionDomain,
            class_data_len,
            class_data,
            new_class_data_len,
            new_class_data,
            environment->mIsRetransformer);
        restoreThrowable(jnienv, outstandingException);
    }
}
jvmtiEnv* retransformableEnvironment(JPLISAgent * agent) {
    jvmtiEnv *          retransformerEnv     = NULL;
    jint                jnierror             = JNI_OK;
    jvmtiCapabilities   desiredCapabilities;
    jvmtiEventCallbacks callbacks;
    jvmtiError          jvmtierror;
    if (agent->mRetransformEnvironment.mJVMTIEnv != NULL) {
        return agent->mRetransformEnvironment.mJVMTIEnv;
    }
    jnierror=agent->mJVM->GetEnv((void **)&retransformerEnv,JVMTI_VERSION_1_1);
    if ( jnierror != JNI_OK ) {
        return NULL;
    }
    jvmtierror = retransformerEnv->GetCapabilities(&desiredCapabilities);
    desiredCapabilities.can_retransform_classes=1;
    if (agent->mNativeMethodPrefixAdded) {
        desiredCapabilities.can_set_native_method_prefix=1;
    }
    jvmtierror = (retransformerEnv)->AddCapabilities(&desiredCapabilities);
    if (jvmtierror != JVMTI_ERROR_NONE) {
        jvmtierror = retransformerEnv->DisposeEnvironment();
        return NULL;
    }
    memset(&callbacks, 0, sizeof(callbacks));
    callbacks.ClassFileLoadHook = &eventHandlerClassFileLoadHook;
    jvmtierror = (retransformerEnv)->SetEventCallbacks(&callbacks,sizeof(callbacks));
    if (jvmtierror == JVMTI_ERROR_NONE) {
        agent->mRetransformEnvironment.mJVMTIEnv = retransformerEnv;
        agent->mRetransformEnvironment.mIsRetransformer = 1;
        jvmtierror = (retransformerEnv)->SetEnvironmentLocalStorage(&(agent->mRetransformEnvironment));
        if (jvmtierror == JVMTI_ERROR_NONE) {
            return retransformerEnv;
        }
    }
    return NULL;
}
void enableNativeMethodPrefixCapability(jvmtiEnv * jvmtienv) {
    jvmtiCapabilities   desiredCapabilities;
    jvmtiError          jvmtierror;
    jvmtierror = (jvmtienv)->GetCapabilities(&desiredCapabilities);
    desiredCapabilities.can_set_native_method_prefix = 1;
    jvmtierror = (jvmtienv)->AddCapabilities(&desiredCapabilities);
}
void addNativeMethodPrefixCapability(JPLISAgent * agent) {
    if (agent->mNativeMethodPrefixAvailable && !agent->mNativeMethodPrefixAdded) {
        jvmtiEnv * jvmtienv = agent->mNormalEnvironment.mJVMTIEnv;
        enableNativeMethodPrefixCapability(jvmtienv);
        jvmtienv = agent->mRetransformEnvironment.mJVMTIEnv;
        if (jvmtienv != NULL) {
            enableNativeMethodPrefixCapability(jvmtienv);
        }
        agent->mNativeMethodPrefixAdded = 1;
    }
}
void addOriginalMethodOrderCapability(JPLISAgent * agent) {
    jvmtiEnv *          jvmtienv = jvmti(agent);
    jvmtiCapabilities   desiredCapabilities;
    jvmtiError          jvmtierror;
    jvmtierror = jvmtienv->GetCapabilities(&desiredCapabilities);
    desiredCapabilities.can_maintain_original_method_order = 1;
    jvmtierror = jvmtienv->AddCapabilities(&desiredCapabilities);
}
void convertCapabilityAttributes(JPLISAgent* agent) {
    addRedefineClassesCapability(agent);
    retransformableEnvironment(agent);
    addNativeMethodPrefixCapability(agent);
    addOriginalMethodOrderCapability(agent);
}
JPLISInitializationError initializeJPLISAgent(JPLISAgent* agent, JavaVM* vm, jvmtiEnv* jvmtienv) {
    jvmtiError      jvmtierror = JVMTI_ERROR_NONE;
    jvmtiPhase      phase;
    agent->mJVM = vm;
    agent->mNormalEnvironment.mJVMTIEnv = jvmtienv;
    agent->mNormalEnvironment.mAgent = agent;
    agent->mNormalEnvironment.mIsRetransformer = 0;
    agent->mRetransformEnvironment.mJVMTIEnv = NULL;
    agent->mRetransformEnvironment.mAgent = agent;
    agent->mRetransformEnvironment.mIsRetransformer = 0;
    agent->mAgentmainCaller = NULL;
    agent->mInstrumentationImpl = NULL;
    agent->mPremainCaller = NULL;
    agent->mTransform = NULL;
    agent->mRedefineAvailable = 0;
    agent->mRedefineAdded = 0;
    agent->mNativeMethodPrefixAvailable = 0;
    agent->mNativeMethodPrefixAdded = 0;
    agent->mAgentClassName = NULL;
    agent->mOptionsString = NULL;
    agent->mJarfile = NULL;
    jvmtierror = (jvmtienv)->SetEnvironmentLocalStorage(
        &(agent->mNormalEnvironment));
    checkCapabilities(agent);
    jvmtierror = (jvmtienv)->GetPhase(&phase);
    if (phase == JVMTI_PHASE_LIVE) {
        return JPLIS_INIT_ERROR_NONE;
    }
    if (phase != JVMTI_PHASE_ONLOAD) {
        return JPLIS_INIT_ERROR_FAILURE;
    }
    //if (jvmtierror == JVMTI_ERROR_NONE ) {
    //    jvmtiEventCallbacks callbacks;
    //    memset(&callbacks, 0, sizeof(callbacks));
    //    callbacks.VMInit = &eventHandlerVMInit;
    //    jvmtierror = (jvmtienv)->SetEventCallbacks(&callbacks,sizeof(callbacks));
    //    check_phase_ret_blob(jvmtierror, JPLIS_INIT_ERROR_FAILURE);
    //}
    if (jvmtierror == JVMTI_ERROR_NONE) {
        jvmtierror = (jvmtienv)->SetEventNotificationMode(
            JVMTI_ENABLE,
            JVMTI_EVENT_VM_INIT,
            NULL /* all threads */);
        check_phase_ret_blob(jvmtierror, JPLIS_INIT_ERROR_FAILURE);
    }
    return (jvmtierror == JVMTI_ERROR_NONE) ? JPLIS_INIT_ERROR_NONE : JPLIS_INIT_ERROR_FAILURE;
}
void deallocateJPLISAgent(jvmtiEnv * jvmtienv, JPLISAgent * agent) {
    deallocate(jvmtienv, agent);
}
JPLISInitializationError createNewJPLISAgent_(JavaVM* vm, JPLISAgent** agent_ptr) {
    JPLISInitializationError initerror = JPLIS_INIT_ERROR_NONE;
    jvmtiEnv* jvmtienv = NULL;
    jint jnierror = JNI_OK;
    *agent_ptr = NULL;
    jnierror = (vm)->GetEnv((void**)&jvmtienv, JVMTI_VERSION_1_1);
    if (jnierror != JNI_OK) {
        initerror = JPLIS_INIT_ERROR_CANNOT_CREATE_NATIVE_AGENT;
    } else {
        JPLISAgent* agent = allocateJPLISAgent(jvmtienv);
        if (agent == NULL) {
            initerror = JPLIS_INIT_ERROR_ALLOCATION_FAILURE;
        } else {
            initerror = initializeJPLISAgent(agent, vm, jvmtienv);
            if (initerror == JPLIS_INIT_ERROR_NONE) {
                *agent_ptr = agent;
            } else {
                deallocateJPLISAgent(jvmtienv, agent);
            }
        }
        if (initerror != JPLIS_INIT_ERROR_NONE) {
            jvmtiError jvmtierror = jvmtienv->DisposeEnvironment();
        }
    }
    return initerror;
}
//===================================================Agent END===================================================
static jvmtiIterationControl JNICALL objectInstanceCallback(jlong class_tag, jlong size, jlong* tag_ptr, void* user_data) {
    *tag_ptr = 10086;
    return JVMTI_ITERATION_CONTINUE;
}
JNIEXPORT jobjectArray JNICALL Java_apphhzp_lib_natives_NativeUtil_getObjectsWithTag(JNIEnv* env,jclass useless, jlong tag) {
    JavaVM* vm;
    env->GetJavaVM(&vm);
    jvmtiEnv* jvmti;
    vm->GetEnv((void**)&jvmti, JVMTI_VERSION_1_1);
    jint count;
    jobject* instances;
    jvmti->GetObjectsWithTags(1, &tag, &count, &instances, NULL);
    jobjectArray re = env->NewObjectArray(count, env->FindClass("java/lang/Object"), NULL);
    for (int i = 0; i < count; i++) {
        env->SetObjectArrayElement(re, i, instances[i]);
    }
    jvmti->Deallocate((unsigned char*)instances);
    return re;
}
JNIEXPORT jobjectArray JNICALL Java_apphhzp_lib_natives_NativeUtil_getInstancesOfClass(JNIEnv* env,jclass obj,jclass klass) {   
    JavaVM* vm;
    env->GetJavaVM(&vm);
    jvmtiEnv* jvmti;
    vm->GetEnv((void**)&jvmti, JVMTI_VERSION_1_1);
    jvmtiCapabilities capabilities = {0};
    capabilities.can_tag_objects = 1;
    jvmti->AddCapabilities(&capabilities);
    jvmti->IterateOverInstancesOfClass(klass, JVMTI_HEAP_OBJECT_EITHER,objectInstanceCallback, NULL);
    jlong tag =10086;
    jint count;
    jobject* instances;
    jvmti->GetObjectsWithTags(1, &tag, &count, &instances, NULL);
    jobjectArray re = env->NewObjectArray(count, klass, NULL);
    for(int i = 0; i < count; i++){
        env->SetObjectArrayElement(re, i, instances[i]);
    }
    jvmti->Deallocate((unsigned char*)instances);
    return re;
}

//================================================Field Agent Start===================================================
#define OBJECT_INST_CLASSNAME "apphhzp/lib/instrumentation/ObjectInstrumentationImpl"
#define OBJECT_INST_CONSTRUCTOR_DESC "(J)V"
#define OBJECT_INST_HandleVMObjectAllocEvent_DESC "(Ljava/lang/Thread;Ljava/lang/Object;Ljava/lang/Class;J)V"
#define OBJECT_INST_HandleObjectFreeEvent_DESC "(J)V"
#define OBJECT_INST_HandleSampledObjectAllocEvent_DESC "(Ljava/lang/Thread;Ljava/lang/Object;Ljava/lang/Class;J)V"
struct  JPLISObjectAgent;
struct _JPLISObjectAgentEnvironment {
    jvmtiEnv *              environment_env;
    JPLISObjectAgent*            object_agent;
    jboolean                useless2;
};
struct JPLISObjectAgent{
    JavaVM_* jvm;
    jvmtiEnv* jvmtienv;
    JNIEnv* jni_env;
    _JPLISObjectAgentEnvironment environment;
    jobject owner;
    jmethodID handle_vm_object_alloc_method;
    jmethodID handle_object_free_method;
    jmethodID handle_sampled_object_alloc_method;
    jboolean can_hook_vm_object_alloc;
    jboolean can_hook_object_free;
    jboolean can_hook_sampled_object_alloc;
};
_JPLISObjectAgentEnvironment* getJPLISObjectAgentEnvironment(jvmtiEnv* jvmtienv) {
    _JPLISObjectAgentEnvironment* environment = NULL;
    jvmtiError         jvmtierror = JVMTI_ERROR_NONE;
    jvmtierror = jvmtienv->GetEnvironmentLocalStorage((void**)&environment);
    if (jvmtierror != JVMTI_ERROR_NONE) {
        environment = NULL;
    }
    return environment;
}
void JNICALL eventHandlerVMObjectAllocHook(jvmtiEnv *jvmti_env,JNIEnv* jni_env,jthread thread,jobject object,jclass object_klass,jlong size){
    _JPLISObjectAgentEnvironment* environment = NULL;
    environment = getJPLISObjectAgentEnvironment(jvmti_env);
    if (environment!=NULL){
        jthrowable outstanding = preserveThrowable(jni_env);
        JPLISObjectAgent* agent = environment->object_agent;
        jobject inst = agent->owner;
        jni_env->CallVoidMethod(inst, agent->handle_vm_object_alloc_method,thread,object,object_klass,size);
        restoreThrowable(jni_env, outstanding);
    }
}
void JNICALL eventHandlerObjectFreeHook(jvmtiEnv *jvmti_env,jlong tag) {
    _JPLISObjectAgentEnvironment* environment = NULL;
    environment = getJPLISObjectAgentEnvironment(jvmti_env);
    if (environment!=NULL){
        
        JPLISObjectAgent* agent = environment->object_agent;
        jthrowable outstanding = preserveThrowable(agent->jni_env);
        jobject inst = agent->owner;
        agent->jni_env->CallVoidMethod(inst, agent->handle_object_free_method,tag);
        restoreThrowable(agent->jni_env, outstanding);
    }
}
void JNICALL eventHandlerSampledObjectAllocHook(jvmtiEnv* jvmti_env,JNIEnv* jni_env,jthread thread,jobject object,jclass object_klass,jlong size){
    _JPLISObjectAgentEnvironment* environment = NULL;
    environment = getJPLISObjectAgentEnvironment(jvmti_env);
    if (environment!=NULL){
        jthrowable outstanding = preserveThrowable(jni_env);
        JPLISObjectAgent* agent = environment->object_agent;
        jobject inst = agent->owner;
        jni_env->CallVoidMethod(inst, agent->handle_sampled_object_alloc_method,thread,object,object_klass,size);
        restoreThrowable(jni_env, outstanding);
    }
}
jvmtiEnv* addObjectHook(JPLISObjectAgent* agent);
JPLISInitializationError createNewJPLISObjectAgent_(JavaVM* vm, JPLISObjectAgent** agent_ptr,JNIEnv_*env);
JNIEXPORT jobject JNICALL Java_apphhzp_lib_natives_NativeUtil_createObjectInstrumentationImpl(JNIEnv* env, jclass useless) {
    JavaVM_* vm = NULL;
    env->GetJavaVM(&vm);
    if (vm==NULL){
        MessageBox(NULL,L"Couldn't get JavaVM!",L"ApphhzpLIB.dll ERR",MB_OK|MB_ICONERROR);
        return NULL;
    }
    JPLISObjectAgent* agent = NULL;
    JPLISInitializationError err = createNewJPLISObjectAgent_(vm,&agent,env);
    if (agent==NULL||err!=JPLIS_INIT_ERROR_NONE){
        MessageBox(NULL, L"Couldn't create localReference for ObjectInstrumentationImpl!", L"ApphhzpLIB.dll ERR", MB_OK | MB_ICONERROR);
        return NULL;
    }
    jclass klass = env->FindClass(OBJECT_INST_CLASSNAME);
    agent->handle_vm_object_alloc_method = env->GetMethodID(klass, "handleVMObjectAllocEvent", OBJECT_INST_HandleVMObjectAllocEvent_DESC);
    agent->handle_object_free_method = env->GetMethodID(klass, "handleObjectFreeEvent", OBJECT_INST_HandleObjectFreeEvent_DESC);
    agent->handle_sampled_object_alloc_method = env->GetMethodID(klass, "handleSampledObjectAllocEvent", OBJECT_INST_HandleSampledObjectAllocEvent_DESC);
    //jmethodID transform_method = env->GetMethodID(klass, "transform", "(Ljava/lang/Module;Ljava/lang/ClassLoader;Ljava/lang/String;Ljava/lang/Class;Ljava/security/ProtectionDomain;[BZ)[B");
    jobject localReference = NULL;
    localReference = env->NewObject(
        klass,
        env->GetMethodID(klass,
            "<init>",
            OBJECT_INST_CONSTRUCTOR_DESC),
        (jlong)agent);
    if (localReference == NULL){
        MessageBox(NULL, L"Couldn't create localReference for ObjectInstrumentationImpl!", L"ApphhzpLIB.dll ERR", MB_OK | MB_ICONERROR);
        return NULL;
    }
    addObjectHook(agent);
    jobject re = NULL;
    re = env->NewGlobalRef(localReference);
    agent->owner = re;
    return re;
}
jvmtiEnv* addObjectHook(JPLISObjectAgent * agent) {
    jint                jnierror             = JNI_OK;
    jvmtiCapabilities   desiredCapabilities;
    jvmtiEventCallbacks callbacks;
    jvmtiError          jvmtierror;
    jvmtierror = agent->jvmtienv->GetCapabilities(&desiredCapabilities);
    desiredCapabilities.can_generate_vm_object_alloc_events = agent->can_hook_vm_object_alloc;
    desiredCapabilities.can_generate_object_free_events = agent->can_hook_object_free;
    desiredCapabilities.can_generate_sampled_object_alloc_events = agent->can_hook_sampled_object_alloc;
    jvmtierror = agent->jvmtienv->AddCapabilities(&desiredCapabilities);
    if (jvmtierror != JVMTI_ERROR_NONE){
        jvmtierror = agent->jvmtienv->DisposeEnvironment();
        return NULL;
    }
    memset(&callbacks, 0, sizeof(callbacks));
    if (agent->can_hook_vm_object_alloc==1){
        callbacks.VMObjectAlloc = &eventHandlerVMObjectAllocHook;
    }
    if (agent->can_hook_object_free==1){
        callbacks.ObjectFree=&eventHandlerObjectFreeHook;
    }
    if (agent->can_hook_sampled_object_alloc==1){
        callbacks.SampledObjectAlloc = &eventHandlerSampledObjectAllocHook;
    }
    jvmtierror = agent->jvmtienv->SetEventCallbacks(&callbacks,sizeof(callbacks));
    agent->environment.environment_env = agent->jvmtienv;
    if (jvmtierror == JVMTI_ERROR_NONE) {
        jvmtierror = agent->jvmtienv->SetEnvironmentLocalStorage(&(agent->environment));
        if (jvmtierror == JVMTI_ERROR_NONE) {
            return agent->jvmtienv;
        }
    }
    return NULL;
}
JPLISInitializationError initializeJPLISObjectAgent(JPLISObjectAgent* agent, JavaVM* vm, jvmtiEnv* jvmtienv) {
    jvmtiError      jvmtierror = JVMTI_ERROR_NONE;
    jvmtiCapabilities   potentialCapabilities;
    jvmtiPhase      phase;
    agent->jvm = vm;
    agent->jvmtienv=jvmtienv;
    agent->environment.environment_env=NULL;
    agent->environment.object_agent=agent;
    agent->environment.useless2 = 0;
    agent->owner = NULL;
    agent->handle_vm_object_alloc_method = NULL;
    agent->handle_object_free_method = NULL;
    agent->handle_sampled_object_alloc_method = NULL;
    agent->can_hook_vm_object_alloc = 0;
    agent->can_hook_object_free = 0;
    agent->can_hook_sampled_object_alloc = 0;
    memset(&potentialCapabilities, 0, sizeof(potentialCapabilities));
    jvmtierror = jvmtienv->GetPotentialCapabilities(&potentialCapabilities);
    if (jvmtierror == JVMTI_ERROR_NONE){
        if (potentialCapabilities.can_generate_vm_object_alloc_events==1) {
            agent->can_hook_vm_object_alloc = 1;
        }
        if (potentialCapabilities.can_generate_object_free_events==1){
            agent->can_hook_object_free = 1;
        }
        if (potentialCapabilities.can_generate_sampled_object_alloc_events == 1) {
            agent->can_hook_sampled_object_alloc = 1;
        }
    }
    return (jvmtierror == JVMTI_ERROR_NONE) ? JPLIS_INIT_ERROR_NONE : JPLIS_INIT_ERROR_FAILURE;
}
void deallocateJPLISObjectAgent(jvmtiEnv * jvmtienv, JPLISObjectAgent * agent) {
    deallocate(jvmtienv, agent);
}
JPLISObjectAgent* allocateJPLISObjectAgent(jvmtiEnv * jvmtienv) {
    return (JPLISObjectAgent *) allocate(jvmtienv,sizeof(JPLISObjectAgent));
}
JPLISInitializationError createNewJPLISObjectAgent_(JavaVM* vm, JPLISObjectAgent** agent_ptr,JNIEnv_ *env) {
    JPLISInitializationError initerror = JPLIS_INIT_ERROR_NONE;
    jvmtiEnv* jvmtienv = NULL;
    jint jnierror = JNI_OK;
    *agent_ptr = NULL;
    jnierror = (vm)->GetEnv((void**)&jvmtienv, JVMTI_VERSION_1_1);
    if (jnierror != JNI_OK) {
        initerror = JPLIS_INIT_ERROR_CANNOT_CREATE_NATIVE_AGENT;
    } else {
        JPLISObjectAgent* agent = allocateJPLISObjectAgent(jvmtienv);
        if (agent == NULL) {
            initerror = JPLIS_INIT_ERROR_ALLOCATION_FAILURE;
        } else {
            initerror = initializeJPLISObjectAgent(agent, vm, jvmtienv);
            if (initerror == JPLIS_INIT_ERROR_NONE) {
                agent->jni_env = env;
                *agent_ptr = agent;
            } else {
                deallocateJPLISObjectAgent(jvmtienv, agent);
            }
        }
        if (initerror != JPLIS_INIT_ERROR_NONE) {
            jvmtiError jvmtierror=jvmtienv->DisposeEnvironment();
        }
    }
    return initerror;
}
JNIEXPORT void JNICALL Java_apphhzp_lib_instrumentation_ObjectInstrumentationImpl_setHeapSamplingInterval0(JNIEnv* env,jobject obj, jlong pointer, jint val) {
    JPLISObjectAgent* agent = (JPLISObjectAgent*)pointer;
    jvmtiEnv* jvmtienv=agent->jvmtienv;
    jvmtienv->SetHeapSamplingInterval(val);
}
JNIEXPORT jboolean JNICALL Java_apphhzp_lib_instrumentation_ObjectInstrumentationImpl_canHookVMObjectAllocEvents0(JNIEnv* env, jobject obj, jlong pointer) {
    JPLISObjectAgent* agent = (JPLISObjectAgent*)pointer;
    return agent->can_hook_vm_object_alloc;
}
JNIEXPORT jboolean JNICALL Java_apphhzp_lib_instrumentation_ObjectInstrumentationImpl_canHookObjectFreeEvents0(JNIEnv* env, jobject obj, jlong pointer) {
    JPLISObjectAgent* agent = (JPLISObjectAgent*)pointer;
    return agent->can_hook_object_free;
}
JNIEXPORT jboolean JNICALL Java_apphhzp_lib_instrumentation_ObjectInstrumentationImpl_canHookSampledObjectAllocEvents0(JNIEnv* env, jobject obj, jlong pointer) {
    JPLISObjectAgent* agent = (JPLISObjectAgent*)pointer;
    return agent->can_hook_sampled_object_alloc;
}
JNIEXPORT void JNICALL Java_apphhzp_lib_instrumentation_ObjectInstrumentationImpl_setHasMonitors(JNIEnv* env, jobject obj, jlong pointer, jboolean has) {
    JPLISObjectAgent* agent = (JPLISObjectAgent*)pointer;
    agent->jvmtienv->SetEventNotificationMode(has?JVMTI_ENABLE:JVMTI_DISABLE, JVMTI_EVENT_VM_OBJECT_ALLOC, NULL);
    agent->jvmtienv->SetEventNotificationMode(has?JVMTI_ENABLE:JVMTI_DISABLE, JVMTI_EVENT_OBJECT_FREE, NULL);
    agent->jvmtienv->SetEventNotificationMode(has?JVMTI_ENABLE:JVMTI_DISABLE, JVMTI_EVENT_SAMPLED_OBJECT_ALLOC, NULL);
}
//================================================Field Agent END===================================================

JNIEXPORT jclass JNICALL Java_apphhzp_lib_natives_NativeUtil_defineClass(JNIEnv* env, jclass cls, jobject loader, jclass lookup, jstring name, jbyteArray data, jint offset, jint length, jobject pd, jboolean initialize, jint flags, jobject classData) {
    
}

