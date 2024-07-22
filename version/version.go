package version

var (
	VersionSuffix = "" // eg. DEV
	VersionTag    = "v0.7.2"
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
