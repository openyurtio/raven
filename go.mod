module github.com/openyurtio/raven

go 1.16

require (
	github.com/EvilSuperstars/go-cidrman v0.0.0-20190607145828-28e79e32899a
	github.com/openyurtio/raven-controller-manager v0.1.1-0.20220712045115-14910b0bce36
	github.com/pkg/errors v0.9.1
	github.com/spf13/cobra v1.6.1
	github.com/spf13/pflag v1.0.5
	github.com/stretchr/testify v1.8.1
	github.com/vdobler/ht v5.3.0+incompatible
	github.com/vishvananda/netlink v1.1.1-0.20220112194529-e5fd1f8193de
	golang.org/x/net v0.0.0-20220607020251-c690dde0001d // indirect
	golang.org/x/sys v0.0.0-20220610221304-9f5ed59c137d // indirect
	golang.zx2c4.com/wireguard/wgctrl v0.0.0-20220504211119-3d4a969bb56b
	google.golang.org/genproto v0.0.0-20220608133413-ed9918b62aac // indirect
	k8s.io/apimachinery v0.23.2
	k8s.io/apiserver v0.23.2
	k8s.io/client-go v0.23.2
	k8s.io/klog/v2 v2.30.0
)

replace (
	github.com/googleapis/gnostic => github.com/googleapis/gnostic v0.5.1
	k8s.io/api => k8s.io/api v0.23.2
	k8s.io/component-base => k8s.io/component-base v0.23.2
)
