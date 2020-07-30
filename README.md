# Frida: Hooking of dynamically loaded classes

If Frida spawns a process `Java.use()` only applies to already loaded classes
(unless a class is already loaded and the wrong ClassLoader is used to get a
reference).

To overcome this, I wrote a small test agent, which replaces

```
Java.use(classname: string) => Java.Wrapper
```

with a callback based version `

```
JavaUseOnceLoaded(classname: string, callback: (Java.Wrapper) => void)
```

The approach is based on hooking `ClassLoader.loadClass()` and keeping track of requested classes in a map.

_There is no cleanup once classes are unloaded and hooking ClassLoader could slow down everything/cause crashes, thus this code is considered to be experimental_

## Usage example

For a usage example see `index.ts`. The demo uses an Android App called
""Simple Activity Recognition App" which loads the class `com.saifyproduction.activityrecognition.BackgroundDetectedActivitiesService` at runtime (once a button is pressed in the app).

If Frida is issued with

```
frida -U --runtime=v8 -l _agent.js --no-pause -f com.saifyproduction.activityrecognition
```

to get attached right after spawning the app, a call to `Java.use("com.saifyproduction.activityrecognition.BackgroundDetectedActivitiesService")` would end up in a Class not found exception, because the app is not loaded, yet.

If the following code is used instead, the callback will run as soon as the class is loaded, while providing a `Java.Wrapper` for the class as parameter (and thus allows hooking the implementation etc etc):

```
JavaUseOnceLoaded("com.saifyproduction.activityrecognition.BackgroundDetectedActivitiesService", clazz => {
    log("dynamic load of class: " + clazz.$className)
})

```

The following demo recording shows how two methods of the aforementioned class are hooked, once the class gets loaded.
Trying to call `Java.use()` directly once the application spawns results in an exception, which is printed first.

[![asciicast](https://asciinema.org/a/jORYR2PwNGWxy7K598cn6weg8.svg)](https://asciinema.org/a/jORYR2PwNGWxy7K598cn6weg8)
