package version

var (
	VersionSuffix = "" // eg. DEV
	VersionTag    = "v0.4.2"
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
