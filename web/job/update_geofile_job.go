package job

import (
	"time"

	"github.com/hasan1808/pro-ui/logger"
	"github.com/hasan1808/pro-ui/web/service"
)

const (
	// GeofileUpdateSchedule is how often the built-in geo data files are refreshed.
	//
	// Daily, because that is roughly how often the upstream rule sets publish and
	// there is nothing to gain from asking more than once per release. The transfer
	// itself is cheap when nothing changed: downloadGeofile issues a conditional GET
	// on the local mtime, so an unchanged file costs one 304 rather than 74MB.
	//
	// The cost of a tick is not zero, though - a file that DID change is followed by
	// an Xray restart, which drops every live connection. Once a day is the most
	// disruption this is worth.
	GeofileUpdateSchedule = "@every 24h"

	// GeofileUpdateStartupDelay is when the first refresh runs after the panel starts.
	//
	// robfig/cron schedules an "@every" job one full interval AFTER the scheduler
	// starts, so with no startup run a host that reboots daily would never refresh at
	// all. Ten minutes rather than immediately: startTask is still bringing up every
	// protocol and restarting Xray, and this job ends in another restart, so it must
	// not land on top of that. It is also longer than the SSL job's five minutes on
	// purpose, so the two do not restart things at the same moment on every boot.
	GeofileUpdateStartupDelay = 10 * time.Minute
)

// UpdateGeofileJob refreshes the built-in geo data files when the operator has
// left auto-update on.
//
// Why this exists: routing rules that name a geosite/geoip category fail SILENTLY
// as the data ages. The file still parses and the core still starts, so nothing
// errors anywhere - the categories are simply months out of date and the rules
// quietly stop matching what the operator thinks they match.
type UpdateGeofileJob struct {
	serverService  service.ServerService
	settingService service.SettingService

	// update overrides the service call so a test can assert the gate without
	// reaching the network. Nil in production, so the zero-value job behaves like
	// every other job in this package.
	update func() error
}

// NewUpdateGeofileJob creates a new geo data refresh job.
func NewUpdateGeofileJob() *UpdateGeofileJob {
	return new(UpdateGeofileJob)
}

// Run refreshes the geo data files if auto-update is on, and does nothing at all
// otherwise.
func (j *UpdateGeofileJob) Run() {
	// The scheduler is built without cron.Recover (web.go), so a panic here takes
	// the whole panel down rather than just this tick. Worth guarding: this job
	// writes files the core parses at startup and then restarts that core.
	defer func() {
		if r := recover(); r != nil {
			logger.Error("geofiles: the auto-update job panicked, the files were NOT refreshed:", r)
		}
	}()

	skipped, err := j.tick()
	switch {
	case err != nil:
		// Warning, not Error: the files already on disk are untouched by a failed
		// download (downloadGeofile renames a temp file into place only once it is
		// complete), so the panel keeps working on yesterday's data.
		logger.Warning("geofiles: the scheduled refresh failed:", err)
	case skipped != "":
		logger.Debug("geofiles: skipping the scheduled refresh,", skipped)
	default:
		logger.Info("geofiles: refreshed the built-in geo data files")
	}
}

// tick is Run without the logging, so the skip paths can be asserted in a test.
// A non-empty reason means nothing was attempted.
func (j *UpdateGeofileJob) tick() (skipped string, err error) {
	on, err := j.settingService.GetGeofileAutoUpdate()
	if err != nil {
		return "", err
	}
	if !on {
		return "auto-update is off", nil
	}

	// Never run on top of an operator who is updating by hand from the Geofiles
	// dialog. UpdateGeofile would serialize behind the per-file lock anyway, but the
	// operator's own run publishes the progress the overview is watching and a second
	// run would take that state out from under it.
	if st := j.serverService.GeofileRunState(); st.Running {
		return "an update started from the panel is already running", nil
	}

	return "", j.updateAll()
}

// updateAll is the one call into the service layer, indirected only so a test can
// stand in for it.
func (j *UpdateGeofileJob) updateAll() error {
	if j.update != nil {
		return j.update()
	}
	// "" means every built-in file. This restarts Xray on the way out, which is the
	// point: the core reads geo data at startup, so a refreshed file that nothing
	// reloads has changed nothing.
	return j.serverService.UpdateGeofile("")
}
