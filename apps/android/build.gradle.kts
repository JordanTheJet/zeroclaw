plugins {
    id("com.android.application") version "8.10.1" apply false
    id("org.jetbrains.kotlin.android") version "2.0.21" apply false
}

// The broadly compatible sideload is the safe default. Running `./gradlew` with no task builds
// only Lite; Full remains available through its explicit flavor task and opt-in property.
defaultTasks(":app:assembleLiteDebug")
