package service

import (
	_ "embed"
	"encoding/json"
	"strings"

	"github.com/hasan1808/pro-ui/logger"
	"github.com/hasan1808/pro-ui/util/common"
	"github.com/hasan1808/pro-ui/xray"
)

// XraySettingService provides business logic for Xray configuration management.
// It handles validation and storage of Xray template configurations.
type XraySettingService struct {
	SettingService
}

func (s *XraySettingService) SaveXraySetting(newXraySettings string) error {
	// The frontend round-trips the whole getXraySetting response back
	// through the textarea, so if it has ever received a wrapped
	// payload (see UnwrapXrayTemplateConfig) it sends that same wrapper
	// back here. Strip it before validation/storage, otherwise we save
	// garbage the next read can't recover from without this same call.
	newXraySettings = UnwrapXrayTemplateConfig(newXraySettings)
	if err := s.CheckXrayConfig(newXraySettings); err != nil {
		return err
	}
	// Pull down any geo data file the new rules reference, before the config that
	// references it becomes the config on disk. Choosing "Iran" in the routing
	// editor writes `ext:geoip_IR.dat:ir`, and on a GEO_LEAN build nothing has put
	// that file there. Saving first and finding out at restart costs the whole
	// core, so fetch here and refuse the save when a file cannot be produced. A
	// rejected config leaves the running one alone.
	//
	// Only files this save INTRODUCES can block it. A reference that was already
	// stored and already broken (a custom geo alias whose source was unreachable at
	// startup, say) is not made worse by an unrelated edit, and refusing every
	// later save over it would leave the operator with no way to edit their way
	// out except by hand-deleting the rule.
	if _, missing := EnsureGeofiles(ExtGeoRefs([]byte(newXraySettings))); len(missing) > 0 {
		already, known := s.storedGeoRefs()
		introduced := missing
		if known {
			introduced = subtractRefs(missing, already)
		}
		if len(introduced) > 0 {
			return common.NewErrorf(
				"routing rules reference geo files that are not installed and could not be downloaded: %s",
				strings.Join(introduced, ", "))
		}
		logger.Warning("saving an Xray config that still references missing geo files:", strings.Join(missing, ", "))
	}
	return s.storeXrayTemplate(newXraySettings)
}

// RepairXrayTemplate re-stores a config that only needed a wrapper peeled off,
// for the healing write getXraySetting does when it reads a nested value.
//
// It skips the geo file check on purpose. Unwrapping introduces no reference the
// stored config did not already have, and this runs from a GET: a download that
// stalls there is the Xray Settings page failing to render, rather than a save
// that takes a moment longer.
func (s *XraySettingService) RepairXrayTemplate(unwrapped string) error {
	if err := s.CheckXrayConfig(unwrapped); err != nil {
		return err
	}
	return s.storeXrayTemplate(unwrapped)
}

func (s *XraySettingService) storeXrayTemplate(template string) error {
	return s.SettingService.saveSetting("xrayTemplateConfig", template)
}

// storedGeoRefs is what the currently saved config already references, and
// whether that could be determined at all. Used to tell a pre-existing broken
// reference from one the incoming save is adding.
//
// known=false means "no idea", and the caller must not block on the comparison:
// a reference that may well have been there all along is not grounds to refuse
// an edit.
func (s *XraySettingService) storedGeoRefs() (refs []string, known bool) {
	stored, err := s.SettingService.GetXrayConfigTemplate()
	if err != nil {
		logger.Warning("could not read the stored Xray config to compare geo references:", err)
		return nil, false
	}
	return ExtGeoRefs([]byte(stored)), true
}

// subtractRefs returns the entries of refs that are not in already.
func subtractRefs(refs, already []string) []string {
	if len(already) == 0 {
		return refs
	}
	seen := make(map[string]struct{}, len(already))
	for _, name := range already {
		seen[name] = struct{}{}
	}
	out := refs[:0:0]
	for _, name := range refs {
		if _, ok := seen[name]; !ok {
			out = append(out, name)
		}
	}
	return out
}

func (s *XraySettingService) CheckXrayConfig(XrayTemplateConfig string) error {
	xrayConfig := &xray.Config{}
	err := json.Unmarshal([]byte(XrayTemplateConfig), xrayConfig)
	if err != nil {
		return common.NewError("xray template config invalid:", err)
	}
	return nil
}

// UnwrapXrayTemplateConfig returns the raw xray config JSON from `raw`,
// peeling off any number of `{ "inboundTags": ..., "outboundTestUrl": ...,
// "xraySetting": <real config> }` response-shaped wrappers that may have
// ended up in the database.
//
// How it got there: getXraySetting used to embed the raw DB value as
// `xraySetting` in its response without checking whether the stored
// value was already that exact response shape. If the frontend then
// saved it verbatim (the textarea is a round-trip of the JSON it was
// handed), the wrapper got persisted — and each subsequent save nested
// another layer, producing the blank Xray Settings page reported in
// issue #4059.
//
// If `raw` does not look like a wrapper, it is returned unchanged.
func UnwrapXrayTemplateConfig(raw string) string {
	const maxDepth = 8 // defensive cap against pathological multi-nest values
	for i := 0; i < maxDepth; i++ {
		var top map[string]json.RawMessage
		if err := json.Unmarshal([]byte(raw), &top); err != nil {
			return raw
		}
		inner, ok := top["xraySetting"]
		if !ok {
			return raw
		}
		// Real xray configs never contain a top-level "xraySetting" key,
		// but they do contain things like "inbounds"/"outbounds"/"api".
		// If any of those are present, we're already at the real config
		// and the "xraySetting" field is either user data or coincidence
		// — don't touch it.
		for _, k := range []string{"inbounds", "outbounds", "routing", "api", "dns", "log", "policy", "stats"} {
			if _, hit := top[k]; hit {
				return raw
			}
		}
		// Peel off one layer.
		unwrapped := string(inner)
		// `xraySetting` may be stored either as a JSON object or as a
		// JSON-encoded string of an object. Handle both.
		var asStr string
		if err := json.Unmarshal(inner, &asStr); err == nil {
			unwrapped = asStr
		}
		raw = unwrapped
	}
	return raw
}
