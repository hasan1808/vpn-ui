package web

import (
	"io/fs"
	"sort"
	"testing"

	"github.com/pelletier/go-toml/v2"
)

// TestTranslationsAreValidToml unmarshals every embedded translation file so a
// malformed key (e.g. a bad bulk-ops i18n insertion) fails here instead of silently
// breaking i18n at runtime.
func TestTranslationsAreValidToml(t *testing.T) {
	entries, err := fs.ReadDir(i18nFS, "translation")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		data, err := i18nFS.ReadFile("translation/" + e.Name())
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		var m map[string]any
		if err := toml.Unmarshal(data, &m); err != nil {
			t.Errorf("%s: invalid TOML: %v", e.Name(), err)
		}
	}
}

func keySet(keys ...string) map[string]bool {
	m := make(map[string]bool, len(keys))
	for _, k := range keys {
		m[k] = true
	}
	return m
}

// knownMissing are en_US keys not yet translated in the other locales (the Core
// Settings + systemd-service panels + setup-required toasts added after the
// fork). They render via the English fallback in web/locale.I18n — readable, not
// blank — so they are tolerated here as a baseline. Shrink this list as
// translations land; TestTranslationKeyParity fails on any en-only key NOT in
// this set, so the gap can never grow silently.
var knownMissing = keySet(
	"pages.inbounds.opDelete", "pages.inbounds.bulkDeleteConfirm",
	"pages.inbounds.opFreeze", "pages.inbounds.opUnfreeze",
	"pages.inbounds.selectAllClients",
	"pages.inbounds.bulkAffected", "pages.inbounds.bulkSkipped",
	"pages.client.freeze", "pages.client.unfreeze", "pages.client.frozen",
	"pages.index.checkUpdate", "pages.index.upToDate", "pages.index.updateAvailable",
	"pages.index.updateNow", "pages.index.updateConfirm", "pages.index.updateStarted",
	"pages.index.updateDownloading", "pages.index.updateInstalling", "pages.index.updateRestarting",
	"pages.index.updateCancel", "pages.index.panelUpdate",
	"pages.index.updateCancelling",
	"pages.index.updateFromFile", "pages.index.updateUploading", "pages.index.updateStaged",
	"pages.index.updateChecking",
	"pages.index.manualUpdate", "pages.index.updateFromUrl",
	"pages.index.updateFromUrlIntro", "pages.index.updateFetch",
	"pages.index.updateSameVersion", "pages.index.updateUnknownVersion",
	"pages.index.updateDowngradeTitle", "pages.index.updateDowngradeBody",
	"pages.index.updateDowngradeConfirmLabel", "pages.index.updateDowngradeFinal",
	"pages.index.updateDowngradeNow",
	"pages.index.updateReleaseNotes", "pages.index.updateNoNotes",
	"pages.index.updateModalTitle", "pages.index.updateModalIntro",
	"pages.index.virtualized", "pages.index.virtYes", "pages.index.virtNo",
	"pages.index.panelLocation", "pages.index.panelLocationError",
	"pages.index.virtContainer",
	// The outbound connectivity card + auto-test: newly added, only en_US + fa_IR
	// translated so far; the English fallback carries the rest.
	"pages.index.outbounds", "pages.index.outboundTestAll",
	"pages.xray.outbound.testAll",

	"pages.core.absent", "pages.core.actions", "pages.core.consoleTitle",
	"pages.core.cores", "pages.core.disabled", "pages.core.editConfig",
	"pages.core.enabled", "pages.core.hideLog", "pages.core.inbounds",
	"pages.core.initSetup", "pages.core.ipForward", "pages.core.iproute",
	"pages.core.kernelModules", "pages.core.loaded", "pages.core.logs",
	"pages.core.missing", "pages.core.nftables", "pages.core.noLogs",
	"pages.core.present", "pages.core.provisionDesc", "pages.core.reRunSetup",
	"pages.core.rebootConfirm", "pages.core.rebootDetails", "pages.core.rebootImpact",
	"pages.core.rebootLater", "pages.core.rebootModulesLabel", "pages.core.rebootNow",
	"pages.core.rebootPkgLabel", "pages.core.rebootTitle", "pages.core.rebootWhat",
	"pages.core.rebooting", "pages.core.rebootingDesc", "pages.core.refresh",
	"pages.core.restart", "pages.core.runSetup", "pages.core.setupDone",
	"pages.core.setupNeededDesc", "pages.core.setupNeededTitle", "pages.core.setupRunning",
	"pages.core.showLog", "pages.core.stateError", "pages.core.stateIdle",
	"pages.core.stateNotInstalled", "pages.core.stateRunning", "pages.core.stateStopped",
	"pages.core.status", "pages.core.stepDaemons", "pages.core.stepForward",
	"pages.core.stepIpsec", "pages.core.stepModules", "pages.core.stop",
	"pages.core.subtitle", "pages.core.system", "pages.core.title", "pages.core.backend",
	"pages.core.toasts.provisioned", "pages.core.toasts.rebooting",
	"pages.core.toasts.restarted", "pages.core.toasts.stopped", "pages.core.version",
	"pages.core.availableCoresTitle", "pages.core.availableCoresDesc",
	"pages.core.addCore", "pages.core.uninstallCore",
	"pages.core.checkAll", "pages.core.uncheckAll",
	"pages.core.installedTag", "pages.core.alreadyInstalled",
	"pages.core.hasInbounds", "pages.core.sharesWith", "pages.core.pickerEmpty",
	"pages.core.pickerSetupTitle", "pages.core.pickerSetupDesc",
	"pages.core.pickerAddTitle", "pages.core.pickerAddDesc",
	"pages.core.pickerUninstallTitle", "pages.core.pickerUninstallDesc",
	"pages.core.pickerInstall", "pages.core.pickerUninstall",
	"pages.core.uninstallRunning", "pages.core.uninstallDone",
	"pages.core.uninstallInboundsTitle", "pages.core.uninstallInboundsBody",
	"pages.core.uninstallInboundsDelete", "pages.core.uninstallInboundsDeleteDesc",
	"pages.core.uninstallInboundsKeep", "pages.core.uninstallInboundsKeepDesc",
	"pages.core.uninstallKept", "pages.core.toasts.uninstalled",
	"pages.core.uninstallConsoleTitle",
	"pages.inbounds.toasts.setupRequired", "pages.inbounds.toasts.setupRequiredOk",
	"pages.inbounds.toasts.setupRequiredTitle", "pages.inbounds.toasts.setupRequiredForProtocol",
	"pages.settings.service.apply", "pages.settings.service.autoRefresh",
	"pages.settings.service.enable", "pages.settings.service.enableDesc",
	"pages.settings.service.installed", "pages.settings.service.liveLog",
	"pages.settings.service.liveLogDesc", "pages.settings.service.loadDefault",
	"pages.settings.service.name", "pages.settings.service.nameDesc",
	"pages.settings.service.noLog", "pages.settings.service.noSystemd",
	"pages.settings.service.onBoot", "pages.settings.service.start",
	"pages.settings.service.startDesc", "pages.settings.service.status",
	"pages.settings.service.statusDesc", "pages.settings.service.unit",
	"pages.settings.service.unitDesc", "pages.settings.serviceSettings",

	// Subscription output templates: newly added, only en_US + fa_IR translated
	// so far; the English fallback carries the rest until translations land.
	"pages.settings.subTemplate", "pages.settings.subTemplateDesc",
	"pages.settings.subTemplateCustom", "pages.settings.subTemplatePreview",
	"pages.settings.subTemplatePreviewDesc", "pages.settings.subTemplatePreviewAccount",
	"pages.settings.subTemplateNoAccounts", "pages.settings.subCustomTemplate",
	"pages.settings.subCustomTemplateDesc", "pages.settings.subTemplateVars",

	"pages.index.importForeignTitle", "pages.index.importForeignDesc",
	"pages.index.importForeignConfirm",
	// The Manual Update picker: which END of the transfer does the work is not
	// guessable from "from URL" versus "from file", so each choice carries a sentence.
	"pages.index.manualUpdateIntro", "pages.index.updateFromUrlDesc",
	"pages.index.updateFromFileDesc",

	"pages.xray.outbound.sshOutHint", "pages.xray.outbound.sshOutNone",
	"pages.xray.outbound.sshOutAdd", "pages.xray.outbound.sshOutTag",
	"pages.xray.outbound.sshOutSocksPort", "pages.xray.outbound.sshOutAddress",
	"pages.xray.outbound.sshOutPort", "pages.xray.outbound.sshOutUsername",
	"pages.xray.outbound.sshOutAuth", "pages.xray.outbound.sshOutPassword",
	"pages.xray.outbound.sshOutKey", "pages.xray.outbound.sshOutKeep",
	"pages.xray.outbound.sshOutPassphrase", "pages.xray.outbound.sshOutKnownHost",
	"pages.xray.outbound.sshOutStatus", "pages.xray.outbound.sshOutUp",
	"pages.xray.outbound.sshOutDown", "pages.xray.outbound.sshOutSaved",

	// The tunnel kinds in the outbound protocol picker, importing a peer's .conf or
	// .ovpn into the form, and the two places the panel has to admit that an outbound
	// byte count is absent rather than zero (the Traffic column marker and the note on
	// the stats switches the tunnels force on).
	"pages.xray.outbound.vpnOutNoDriver", "pages.xray.outbound.vpnOutOpenCore",
	"pages.xray.outbound.vpnOutSendThroughHelp",
	"pages.xray.outbound.vpnOutImport", "pages.xray.outbound.vpnOutImportPick",
	"pages.xray.outbound.vpnOutImportDone", "pages.xray.outbound.vpnOutImportEmpty",
	"pages.xray.outbound.vpnOutImportUnreadable", "pages.xray.outbound.vpnOutImportMalformed",
	"pages.xray.outbound.vpnOutImportNotWg", "pages.xray.outbound.vpnOutImportIgnored",
	"pages.xray.outbound.vpnOutImportKept",
	"pages.xray.outbound.trafficUnmeasured", "pages.xray.outbound.trafficUnmeasuredDesc",
	"pages.xray.statsOutboundForced",

	// Client VPN tunnels as outbounds (the form's per-kind fields).
	"pages.xray.outbound.vpnOutAdd", "pages.xray.outbound.vpnOutKind",
	"pages.xray.outbound.vpnOutStatus", "pages.xray.outbound.vpnOutUp",
	"pages.xray.outbound.vpnOutDown", "pages.xray.outbound.vpnOutKeep",
	"pages.xray.outbound.vpnOutKindChanged", "pages.xray.outbound.vpnOutAwgHeadersHelp",
	"pages.xray.outbound.vpnOutClear", "pages.xray.outbound.vpnOutWillClear",
	"pages.xray.outbound.vpnOutExtraHelp",
	"pages.xray.outbound.vpnOutServer", "pages.xray.outbound.vpnOutEndpoint",
	"pages.xray.outbound.vpnOutTunAddress", "pages.xray.outbound.vpnOutLocalAddress",
	"pages.xray.outbound.vpnOutUsername", "pages.xray.outbound.vpnOutPassword",
	"pages.xray.outbound.vpnOutPrivateKey", "pages.xray.outbound.vpnOutPeerKey",
	"pages.xray.outbound.vpnOutPeerAddress", "pages.xray.outbound.vpnOutPresharedKey",
	"pages.xray.outbound.vpnOutKeepAlive", "pages.xray.outbound.vpnOutPort",
	"pages.xray.outbound.vpnOutProto", "pages.xray.outbound.vpnOutProfile",
	"pages.xray.outbound.vpnOutTlsAuth", "pages.xray.outbound.vpnOutTlsCrypt",
	"pages.xray.outbound.vpnOutRemoteCertTls", "pages.xray.outbound.vpnOutExtra",
	"pages.xray.outbound.vpnOutAuthMode", "pages.xray.outbound.vpnOutAuthProto",
	"pages.xray.outbound.vpnOutPsk",
	"pages.xray.outbound.vpnOutIpsec", "pages.xray.outbound.vpnOutIpsecPsk",
	"pages.xray.outbound.vpnOutIpsecPskHelp",
	"pages.xray.outbound.vpnOutIpsecRemoteId", "pages.xray.outbound.vpnOutIpsecLocalId",
	"pages.xray.outbound.vpnOutIkeVersion",
	"pages.xray.outbound.vpnOutFou", "pages.xray.outbound.vpnOutFouPort",
	"pages.xray.outbound.vpnOutLocalId", "pages.xray.outbound.vpnOutServerId",
	"pages.xray.outbound.vpnOutRemoteTs", "pages.xray.outbound.vpnOutTlsUseFile",
	"pages.xray.outbound.vpnOutCert", "pages.xray.outbound.vpnOutKey",
	"pages.xray.outbound.vpnOutCaCert", "pages.xray.outbound.vpnOutCertFile",
	"pages.xray.outbound.vpnOutKeyFile", "pages.xray.outbound.vpnOutCaCertFile",
	"pages.xray.outbound.vpnOutInsecure", "pages.xray.outbound.vpnOutProxy",
	"pages.xray.outbound.vpnOutMppe", "pages.xray.outbound.vpnOutMppeHelp",
	"pages.xray.outbound.vpnOutAuthGroup", "pages.xray.outbound.vpnOutTotpSecret",
	"pages.xray.outbound.vpnOutKeyPassword", "pages.xray.outbound.vpnOutNoDtls",
	"pages.xray.outbound.vpnOutServerCert", "pages.xray.outbound.vpnOutOcProtocol",
)

// flattenKeys collapses nested TOML tables into dotted keys (e.g. "pages.core.title").
func flattenKeys(prefix string, m map[string]any, out map[string]bool) {
	for k, v := range m {
		key := k
		if prefix != "" {
			key = prefix + "." + k
		}
		if sub, ok := v.(map[string]any); ok {
			flattenKeys(key, sub, out)
		} else {
			out[key] = true
		}
	}
}

func loadTranslationKeys(t *testing.T, name string) map[string]bool {
	t.Helper()
	data, err := i18nFS.ReadFile("translation/" + name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	var m map[string]any
	if err := toml.Unmarshal(data, &m); err != nil {
		t.Fatalf("%s: invalid TOML: %v", name, err)
	}
	keys := make(map[string]bool)
	flattenKeys("", m, keys)
	return keys
}

// TestTranslationKeyParity fails when any locale is missing an en_US key that is
// not in the knownMissing baseline — i.e. someone added an English-only string.
// Without this guard such a key renders blank (or English-fallback) for every
// non-English user and nobody notices. Fix a failure by translating the key in
// every locale, or (if intentionally deferred) adding it to knownMissing.
func TestTranslationKeyParity(t *testing.T) {
	const ref = "translate.en_US.toml"
	refKeys := loadTranslationKeys(t, ref)

	entries, err := fs.ReadDir(i18nFS, "translation")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() || e.Name() == ref {
			continue
		}
		locKeys := loadTranslationKeys(t, e.Name())
		var newlyMissing []string
		for k := range refKeys {
			if !locKeys[k] && !knownMissing[k] {
				newlyMissing = append(newlyMissing, k)
			}
		}
		if len(newlyMissing) > 0 {
			sort.Strings(newlyMissing)
			t.Errorf("%s: %d en_US key(s) missing and not baselined "+
				"(translate them or add to knownMissing): %v",
				e.Name(), len(newlyMissing), newlyMissing)
		}
	}
}
