import SwiftUI

struct SSHAgentSettingsView: View {
    @ObservedObject var viewModel: SSHAgentViewModel
    var body: some View {
        Section("SSH Agent") {
            Toggle("Enable SSH agent", isOn: Binding(get: { viewModel.enabled }, set: viewModel.setEnabled))
                .accessibilityValue(viewModel.enabled ? "Enabled" : "Disabled")
            Text(viewModel.status).font(Typography.fieldLabel)
            Text(viewModel.socketPath)
                .font(Typography.utility)
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
                .accessibilityLabel("SSH agent socket path: \(viewModel.socketPath)")
            Text("Point SSH_AUTH_SOCK to this path. SSH requests require an unlocked vault. Verified host connections can be approved until the vault locks.")
                .font(Typography.fieldLabel)
                .fixedSize(horizontal: false, vertical: true)
            if let error = viewModel.errorMessage {
                Text(error).foregroundStyle(.red)
                    .font(Typography.fieldLabel)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }
}

struct SSHAgentApprovalView: View {
    @ObservedObject var viewModel: SSHAgentViewModel
    @Environment(\.dismiss) private var dismiss
    var body: some View {
        VStack(alignment: .leading, spacing: Spacing.headerGap) {
            if let request = viewModel.approval {
                Text("Allow SSH key access?").font(Typography.sectionHeader)
                    .accessibilityAddTraits(.isHeader)
                Text(request.keyName).font(Typography.fieldValue)
                Text(request.fingerprint).font(Typography.utility).textSelection(.enabled)
                Text("SSH username: \(request.username)").font(Typography.fieldValue)
                if let host = request.hostFingerprint {
                    Text("Verified session host key: \(host)").font(Typography.utility)
                        .textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
                    ForEach(Array(request.forwardingHostFingerprints.enumerated()), id: \.offset) { index, fingerprint in
                        Text("Forwarding host \(index + 1): \(fingerprint)").font(Typography.utility)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
                Text(request.hostFingerprint == nil
                     ? "No verified session binding. Allow only a connection you initiated."
                     : "SSH verifies the hostname. Allow until vault locks remembers this key, username and host-key path in memory.")
                    .font(Typography.fieldLabel)
                    .fixedSize(horizontal: false, vertical: true)
                HStack {
                    Spacer()
                    Button("Deny") { viewModel.respond(request, allow: false); dismiss() }
                        .keyboardShortcut(.cancelAction)
                    if request.hostFingerprint != nil {
                        Button("Allow until vault locks") {
                            viewModel.respond(request, allow: true, rememberUntilLock: true); dismiss()
                        }
                        .accessibilityLabel("Allow this SSH key for this username and host path until the vault locks")
                    }
                    Button("Allow Once") { viewModel.respond(request, allow: true); dismiss() }
                        .accessibilityLabel("Allow this SSH key use once")
                }
                .padding(.top, Spacing.cardTop)
            }
        }
        .padding(Spacing.pageMargin)
        .frame(width: 480)
        .background(SSHApprovalWindowAnchor(requestID: viewModel.approval?.id)
            .frame(width: 0, height: 0)
            .allowsHitTesting(false))
        .onChange(of: viewModel.approval) { _, request in if request == nil { dismiss() } }
        .onDisappear {
            if let request = viewModel.approval { viewModel.respond(request, allow: false) }
        }
    }
}
