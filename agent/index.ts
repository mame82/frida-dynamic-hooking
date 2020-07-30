import { log } from "./logger"
import { JavaUseOnceLoaded } from "./dyn_use"

// Test for dynamic hooking of Java class loaded at runtime by an Android app
// Test app: "Simple Activity Recognition App"
// Playstore: https://play.google.com/store/apps/details?id=com.saifyproduction.activityrecognition
//
// To spawn the app and hook it dynamically run:
//    frida -U --runtime=v8 -l _agent.js --no-pause -f com.saifyproduction.activityrecognition

Java.performNow(() => {
  let dynamicClassName =
    "com.saifyproduction.activityrecognition.BackgroundDetectedActivitiesService"

  // Error on direct class usage (print exception to console)
  log("Trying Java.use() on " + dynamicClassName + "...")
  try {
    let clazz = Java.use(dynamicClassName)
  } catch (e) {
    console.log(Java.use("android.util.Log").getStackTraceString(e))
  }

  log(
    "Registering callbacks with JavaUseOnceLoaded for " +
      dynamicClassName +
      "..."
  )

  // first callback only for printing
  JavaUseOnceLoaded(dynamicClassName, clazz => {
    log("dynamic use 1 of class: " + clazz.$className)
  })

  // 2nd callback for hooking (and testing of multiple callbacks on same class)
  JavaUseOnceLoaded(dynamicClassName, clazz => {
    log("dynamic use 2 to place hooks ...")
    log("... on method requestActivityUpdatesButtonHandler()")
    clazz.requestActivityUpdatesButtonHandler.implementation = function() {
      log("called hook requestActivityUpdatesButtonHandler()")
      return this.requestActivityUpdatesButtonHandler()
    }
    log("... on method removeActivityUpdatesButtonHandler()")
    clazz.removeActivityUpdatesButtonHandler.implementation = function() {
      log("called hook removeActivityUpdatesButtonHandler()")
      return this.removeActivityUpdatesButtonHandler()
    }
  })
})
