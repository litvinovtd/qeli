import Dispatch
import NetworkExtension

// A Network Extension packaged as a system extension has an executable entry point rather
// than an app-extension principal entry point. macOS creates the provider classes listed in
// NEProviderClasses after this switches the process into NetworkExtension mode.
NEProvider.startSystemExtensionMode()
dispatchMain()
