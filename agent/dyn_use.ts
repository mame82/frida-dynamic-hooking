const DEBUG = false

type CallBackSet = Set<UseClassOnceLoadedCallback>
let callbackMap = new Map<string, CallBackSet>()

export function log(message: string): void {
  if (DEBUG) console.log(message)
}

function hookLoadClass() {
  var clazzClassLoader = Java.use("java.lang.ClassLoader")
  clazzClassLoader.loadClass.overload(
    "java.lang.String",
    "boolean"
  ).implementation = function(name: string, resolve: boolean) {
    try {
      var result = this.loadClass(name, resolve)
      log("loaded class: " + name)
      if (callbackMap.has(name)) {
        // trigger callbacks for this class
        let classLoader = this
        let clazz = Java.ClassFactory.get(classLoader).use(name)
        let callbacks = callbackMap.get(name)
        if (callbacks !== undefined) {
          for (let callback of callbacks) {
            callback(clazz)
          }
        }
      }
      return result
    } catch (e) {
      log("exception loading class: " + name)
      throw e
    } finally {
    }
  }
}

type UseClassOnceLoadedCallback = (clazz: Java.Wrapper<{}>) => void

export function JavaUseOnceLoaded<T extends Java.Members<T> = {}>(
  className: string,
  callback: UseClassOnceLoadedCallback
): void {
  // if class is already loaded, call callback immediately
  try {
    callback(Java.use(className))
    return
  } catch (e) {
    // ToDo: check if ClassNotFound, assume this for now

    // if callbacks for this class exist already, add the new one, else add a new set with the callback
    // Caution: if the code could be called concurrently, this whole part has to be synced
    if (callbackMap.has(className)) {
      let callbackSet = callbackMap.get(className)
      if (callbackSet !== undefined) callbackSet.add(callback) // else should not happen (currently no entry gets deleted)
    } else {
      let newCallbackSet = new Set<UseClassOnceLoadedCallback>()
      newCallbackSet.add(callback)
      callbackMap.set(className, newCallbackSet)
    }
  }
}

Java.perform(hookLoadClass)
