//! JNI bridge for Android (Kotlin or Java) and any JVM.
//! Kotlin:  object ByoaiChain { init { System.loadLibrary("byoai_chain") }
//!                              @JvmStatic external fun call(request: String): String }
//! (declared in package co.byoai.chain, class ByoaiChain; same domain as co.byoai.swornverified)
use jni::objects::{JClass, JString};
use jni::sys::jstring;
use jni::JNIEnv;

#[no_mangle]
pub extern "system" fn Java_co_byoai_chain_ByoaiChain_call<'l>(mut env: JNIEnv<'l>, _class: JClass<'l>, request: JString<'l>) -> jstring {
    let req: String = match env.get_string(&request) {
        Ok(s) => s.into(),
        Err(_) => String::from("{\"op\":\"\"}"),
    };
    let resp = crate::api::call_json(&req);
    match env.new_string(resp) {
        Ok(s) => s.into_raw(),
        Err(_) => core::ptr::null_mut(),
    }
}
