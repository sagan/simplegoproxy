package version

var (
	VersionSuffix = "" // eg. DEV
	VersionTag    = "v0.2.0"
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
