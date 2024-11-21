package kube


type Device struct {
	Name string
	Node string
}

type Node struct {
        IP string
	MAC string
}

var kubeconfig string
var DevicePortMap = make(map[string]uint16)
var DeviceNodeMap = make(map[uint16]Node)
var PORTMIN = uint16(20000)
var PORTMAX = uint16(30000)


func getKubeClient() {

	//kubeconfig := "/etc/k3s/admin.conf"
	//config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	//if err != nil {
	//	log.Fatalf("Error building kubeconfig: %v", err)
	//}
	//fmt.Print(config)

}

func Start() {
    // Using kubernetes client to get device and node Info	
    getKubeClient()
}

func GetDevicePortMap() map[string]uint16 {
	return DevicePortMap
}

func GetDeviceNodeMap() map[uint16]Node {
	return DeviceNodeMap
}
