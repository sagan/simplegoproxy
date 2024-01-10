package version

var (
	VersionSuffix = "" // eg. DEV
	VersionTag    = "v0.5"
	Version       = ""
)

func init() {
	if Version == "" {
		if VersionSuffix == "" {
			Version = VersionTag
		} else {
			Version = VersionTag + "-" + VersionSuffix
		}
	}
}
