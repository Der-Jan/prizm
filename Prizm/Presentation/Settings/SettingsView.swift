import LocalAuthentication
import SwiftUI

/// macOS Settings window (⌘,).
///
/// Currently contains a Security section with the biometric unlock toggle.
/// The Security section is hidden entirely when the device has no biometrics.
struct SettingsView: View {

    let authRepository: any AuthRepository
    @ObservedObject var sshAgent: SSHAgentViewModel

    private var deviceHasBiometrics: Bool {
        LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
    }

    var body: some View {
        Form {
            SSHAgentSettingsView(viewModel: sshAgent)
            if deviceHasBiometrics {
                Section("Security") {
                    BiometricUnlockToggle(authRepository: authRepository)
                }
            }
        }
        .formStyle(.grouped)
        .frame(width: 400)
        .padding()
    }
}
