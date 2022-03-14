module github.com/openyurtio/raven

go 1.15

require (
	github.com/EvilSuperstars/go-cidrman v0.0.0-20190607145828-28e79e32899a
	github.com/fsnotify/fsnotify v1.5.1 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/google/go-cmp v0.5.6 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/openyurtio/raven-controller-manager v0.0.0-20220306054844-a4d7404ef721
	github.com/spf13/cobra v1.0.0
	github.com/spf13/pflag v1.0.5
	github.com/vdobler/ht v5.3.0+incompatible
	github.com/vishvananda/netlink v1.1.0
	k8s.io/apimachinery v0.20.11
	k8s.io/apiserver v0.20.11
	k8s.io/client-go v0.20.11
	k8s.io/klog/v2 v2.9.0

)

replace (
	github.com/googleapis/gnostic => github.com/googleapis/gnostic v0.4.1
	google.golang.org/grpc => google.golang.org/grpc v1.27.1
	k8s.io/api => k8s.io/api v0.20.11
	k8s.io/component-base => k8s.io/component-base v0.20.11
)
