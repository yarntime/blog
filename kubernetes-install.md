#kubernetes+calico+nfs环境部署

主机说明： 

  * 系统版本：centos7.2，Linux kernel 3.10.0及以上版本。
  * 系统规格：>=4CPU，>=4GRAM，120G磁盘(使用lvm管理，可动态扩容)。

主机规划：  

| 角色        | 主机名      | IP  |  说明 |
| ----------- |:---------: |:-----:|:-----|
| master,etcd         | master     | 172.16.10.2 | etcd,kubernetes(apiserver,scheduler,controller-manager),calico |
| minion     | minion1       | 172.16.10.3 |  kubernetes(kubelet,proxy),docker,calico |
| minion     | minion2       | 172.16.10.4 |  kubernetes(kubelet,proxy),docker,calico |
| registry     | registry       | 172.16.10.5 |  registry |
| nfsserver  | nfsserver     | 172.16.10.6|   nfs-server |

软件： 
  
  * etcd   v2.2.5
  * docker v1.9.1
  * kubernetes二进制包： 
    * kubectl v1.2.0     
    * kubelet v1.2.0      
    * kube-proxy v1.2.0      
    * kube-scheduler v1.2.0      
    * kube-controller-manager v1.2.0      
    * kube-apiserver v1.2.0 
    * registry.access.redhat.com/rhel7/pod-infrastructure:latest（镜像）
  * calico：  
    * calicoctl  v0.18.0
    * calico/node:v0.18.0  （镜像）
    * calico  v1.1.0
    * calico-ipam  v1.1.0
    * calico/k8s-policy-agent:v0.1.2  （镜像）
    * policy  
  * easyrsa3
    

##安装kubernetes集群

1.准备安装源  
建议使用阿里源替换系统自带的源  
配置kubernetes安装源  
关闭selinux: setenforce 0

2.安装kubernetes master节点  
yum install kubernetes etcd -y 安装kubernetes的所有服务。
    
    1）配置crt通信证书
    1.1） 配置apiserver crt证书：
    下载easyrsa3：
    curl -L -O https://storage.googleapis.com/kubernetes-release/easy-rsa/easy-rsa.tar.gz
    tar xzf easy-rsa.tar.gz
    cd easy-rsa-master/easyrsa3
    ./easyrsa init-pki
    创建CA：
    ./easyrsa --batch "--req-cn=${MASTER_IP}@`date +%s`" build-ca nopass  （如果要使用默认的service访问kubernetes集群，使用--req-cn=*）
    生成服务使用的cert和key：
    ./easyrsa --subject-alt-name="IP:${MASTER_IP}" build-server-full kubernetes-master nopass(如果要使用默认的service访问kubernetes集群，要在IP后边配置service的IP：IP:${MASTER_IP}，IP:${SERVICE_IP})*
    mkdir -p /srv/kubernetes  
    cp pki/ca.crt /srv/kubernetes/
    cp pki/issued/kubernetes-master.crt /srv/kubernetes/server.cert  
    cp pki/issued/kubernetes-master.key /srv/kubernetes/server.key

    1.2）配置ServiceAccount:
    openssl genrsa -out /srv/kubernetes/serviceaccount.key 2048

    chmod +x /srv/kubernetes/*
    
    2）配置etcd服务
    vi /etc/etcd/etcd.conf
    修改etcd监听的网卡和端口，使服务能够在集群内访问。

    systemctl enable etcd
    systemctl restart etcd  

    3）配置apiserver
    vi /etc/kubernetes/config
    将KUBE_MASTER的值修改为正确的IP地址。
    # logging to stderr means we get it in the systemd journal  
    KUBE_LOGTOSTDERR="--logtostderr=true"

    # journal message level, 0 is debug
    KUBE_LOG_LEVEL="--v=0"

    # Should this cluster be allowed to run privileged docker containers
    KUBE_ALLOW_PRIV="--allow-privileged=true"

    # How the controller-manager, scheduler, and proxy find the apiserver
    KUBE_MASTER="--master=http://master:8080"

    vi /etc/kubernetes/apiserver
    修改apiserver监听的网卡和端口，并配置使用的etcd集群。注意增加apiserver的证书设置。
    # The address on the local server to listen to.
    KUBE_API_ADDRESS="--insecure-bind-address=0.0.0.0"

    # The port on the local server to listen on.
    # KUBE_API_PORT="--port=8080"
    KUBE_API_PORT="--insecure-port=8080"
    # Port minions listen on
    # KUBELET_PORT="--kubelet-port=10250"

    # Comma separated list of nodes in the etcd cluster
    KUBE_ETCD_SERVERS="--etcd-servers=http://master:2379"

    # Address range to use for services
    KUBE_SERVICE_ADDRESSES="--service-cluster-ip-range=10.254.0.0/16"

    # default admission control policies
    KUBE_ADMISSION_CONTROL="--admission-control=NamespaceLifecycle,NamespaceExists,LimitRanger,SecurityContextDeny,ServiceAccount,ResourceQuota"

    # Add your own!
    KUBE_API_ARGS="--client-ca-file=/srv/kubernetes/ca.crt --tls-cert-file=/srv/kubernetes/server.crt --tls-private-key-file=/srv/kubernetes/server.key --service_account_key_file=/srv/kubernetes/serviceaccount.key"

    
    4）配置controller-manager
    vi /etc/kubernetes/controller-manager
    增加证书设置
    # Add your own!
    KUBE_CONTROLLER_MANAGER_ARGS="--root-ca-file=/srv/kubernetes/ca.crt --service_account_private_key_file=/srv/kubernetes/server.key"

    5）启动master上的服务
    
    for SERVICES in etcd kube-apiserver kube-controller-manager kube-scheduler; do 
	    systemctl restart $SERVICES
	    systemctl enable $SERVICES
	    systemctl status $SERVICES done

3.安装kubernetes minion节点
    yum install kubernetes -y
    
    1）配置kubelet
    vi /etc/kubernetes/config
    将KUBE_MASTER的值修改为正确的IP地址。
    # logging to stderr means we get it in the systemd journal
    KUBE_LOGTOSTDERR="--logtostderr=true"

    # journal message level, 0 is debug
    KUBE_LOG_LEVEL="--v=0"

    # Should this cluster be allowed to run privileged docker containers
    KUBE_ALLOW_PRIV="--allow-privileged=true"

    # How the controller-manager, scheduler, and proxy find the apiserver
    KUBE_MASTER="--master=http://master:8080"

    vi /etc/kubernetes/kubelet
    # The address for the info server to serve on (set to 0.0.0.0 or "" for all interfaces)
    KUBELET_ADDRESS="--address=0.0.0.0"

    # The port for the info server to serve on
    # KUBELET_PORT="--port=10250"

    # You may leave this blank to use the actual hostname
    KUBELET_HOSTNAME="--hostname-override=${YOUR_HOST_NAME}"

    # location of the api-server
    KUBELET_API_SERVER="--api-servers=http://master:8080"

    # pod infrastructure container
    KUBELET_POD_INFRA_CONTAINER="--pod-infra-container-    image=registry.access.redhat.com/rhel7/pod-infrastructure:latest"

    # Add your own!
    KUBELET_ARGS=""
    
    2）配置kube-proxy
    vi /etc/kuerbnetes/proxy，可以配置proxy模式
    # Add your own!
    KUBE_PROXY_ARGS=" --proxy-mode=iptables"
    
    3）启动minon上的服务
    for SERVICES in kube-proxy kubelet docker; do 
        systemctl restart $SERVICES
        systemctl enable $SERVICES
        systemctl status $SERVICESdone
4.检查kubernetes 集群状态    
等服务启动完成后，在master节点上检查集群状况。测试环境上master上也部署了成了minion节点。 

    [root@master ~]# kubectl get nodes  
    NAME      LABELS                           STATUS    AGE
    master    kubernetes.io/hostname=master    Ready     6d
    minion1   kubernetes.io/hostname=minion1   Ready     6d
    minion2   kubernetes.io/hostname=minion2   Ready     6d

## 安装Calico  

1.节点安装calico （使用v0.18.0版本）  

    wget -o /usr/bin/calicoctl https://github.com/projectcalico/calico-containers/releases/download/v0.18.0/calicoctl  
    chmod +x /usr/bin/calicoctl  
创建文件/etc/systemd/calico-node，设置etcd集群服务地址:  

    [Unit]  
    Description=calicoctl node  
    After=docker.service  
    Requires=docker.service  
    [Service]     
    User=root
    Environment=ETCD_AUTHORITY=master:4001
    PermissionsStartOnly=true
    ExecStart=/usr/bin/calicoctl node --detach=false
    Restart=always
    RestartSec=10
    [Install]
    WantedBy=multi-user.target
将calico-node配置成开机启动服务，并启动。  
在环境变量中增加ETCD_AUTHORITY=master:4001的配置  

    systemctl enable /etc/systemd/calico-node.service
    service calico-node restart  

将会使用镜像calico/node:v0.18.0，启动服务。

2.在所有minion节点上，安装calico-cni扩展  

    wget -N -P /opt/cni/bin https://github.com/projectcalico/calico-cni/releases/download/v1.1.0/calico chmod +x /opt/cni/bin/calico
    wget -N -P /opt/cni/bin https://github.com/projectcalico/calico-cni/releases/download/v1.1.0/calico-ipam
    chmod +x /opt/cni/bin/calico-ipam  

配置cni网络声明：  

    $ cat /etc/cni/net.d/10-calico.conf
    {
        "name" : "calico-k8s-network",
        "type" : "calico",
        "etcd_authority" : "master:4001",
        "log_level" : "info",
        "ipam" : {
            "type" : "calico-ipam"
        }
    }

如果是在阿里云上部署，需要设置calico使用ipip，用如下命令查看：

    calicoctl pool show --ipv4
如果显示

    +----------------+-------------------+
    |   IPv4 CIDR    |      Options      |
    +----------------+-------------------+
    | 192.168.0.0/16 | ipip,nat-outgoing |
    +----------------+-------------------+
表示已启用ipip，否则根据提示删除ip池，重新添加并使用选项--ipip --nat-outgoing。

查看默认规则是否正确：

    calicoctl profile calico-k8s-network rule show
如果显示

    Inbound rules:
        1 allow
    Outbound rules:
        1 allow
表示默认规则正确。

3.部署policy-agent
使用下面的yaml文件部署policy-agent，其机制为监听kubernetes 中pod和namespace的变化，namespace中network policy的配置变化，有policy-agent写入到calico的etcd存储中，然后直接由每个节点上的felix转换为iptables规则。  

    apiVersion: v1
    kind: Namespace
    metadata:
      name: calico-system
    ---
    apiVersion: v1
    kind: ReplicationController
    metadata:
      name: calico-policy-agent
      namespace: calico-system
      labels:
        version: v0.1.2
        projectcalico.org/app: "policy-agent"
    spec:
      replicas: 2
      selector:
        version: v0.1.2
        projectcalico.org/app: "policy-agent"
      template:
        metadata:
          labels:
            version: v0.1.2
            projectcalico.org/app: "policy-agent"
        spec:
          containers:
            - name: policyagent
              image: 172.16.10.5:5000/calico/k8s-policy-agent:v0.1.2
              imagePullPolicy: IfNotPresent
              env:
              - name: ETCD_ENDPOINTS
                value: "http://172.16.10.2:2379"  
部署完成后，等待服务启动。文件中的env是让pod使用环境变量方式访问ETCD，如果kubernetes集群中安装了DNS，可以删掉环境变量的设置，使用dns访问ETCD服务。
在master节点上，policy用于操作network policy对象实现网络隔离的动态控制。  

    wget https://github.com/projectcalico/k8s-policy/releases/download/v0.1.1/policy
    chmod +x ./policy
 
4.修改kubernetes配置  
设置kube-proxy服务的proxy-mode配置为iptables，修改配置文件/etc/kubernetes/proxy： 

    ###
    # kubernetes proxy config
    # default config should be adequate
    # Add your own!
    KUBE_PROXY_ARGS=" --proxy-mode=iptables"

设置kubelet的network-plugin为cni，修改配置文件/usr/lib/systemd/system/kubelet.service： 

    [Unit]
    Description=Kubernetes Kubelet Server
    Documentation=https://github.com/GoogleCloudPlatform/kubernetes
    After=docker.service
    Requires=docker.service
    [Service]
    WorkingDirectory=/var/lib/kubelet
    EnvironmentFile=-/etc/kubernetes/config
    EnvironmentFile=-/etc/kubernetes/kubelet
    ExecStart=/usr/bin/kubelet \
    --network-plugin-dir=/etc/cni/net.d \
    --network-plugin=cni \
    $KUBE_LOGTOSTDERR \
    $KUBE_LOG_LEVEL \
    $KUBELET_API_SERVER \
    $KUBELET_ADDRESS \
    $KUBELET_PORT \
    $KUBELET_HOSTNAME \
    $KUBE_ALLOW_PRIV \
    $KUBELET_POD_INFRA_CONTAINER \
    $KUBELET_ARGS
    Restart=on-failure
    [Install]
    WantedBy=multi-user.target

重启相关服务： 

    service kubelet restart
    service kube-proxy restart

5.验证网络环境是否满足kubernetes需求：  
1) 创建一个rc，副本数量和集群的minion节点一致。  
2) 测试主机到pod通信：主机 ping 本机PodIp, 主机ping 其它主机PodIp。Pod内部ping宿主机Ip，Pod内部ping其它主机Ip。  
3) 测试cluster ip通信：创建service，后端使用可用的Pod服务。在Pod所在minion，使用serviceIp+port访问服务。在其它minion，使用serviceIp+port访问服务。  
4) 测试nodePort通信：使用minion本机IP+nodeport访问服务。使用其它minion ip+nodeport访问服务。  
如果以上测试全部通过，则网络配置正确，否则需要排查问题。
如果排查后配置全部正确，但是kubermetes网络某些环节不通，可以在所有节点执行：

    calicoctl node
命令，重新初始化calico网络的链接。

## 安装nfs服务

1.安装nfs相关服务  
   
    yum install nfs-server  
    yum install nfs  
    yum install rpcbind nfs-utils

2.添加共享目录  

    /share *(rw,insecure,sync,no_subtree_check,no_root_squash)
    /mysql *(rw,insecure,sync,no_subtree_check,no_root_squash)
上述共享目录的配置一定要写上，否则在使用过程中可能出现Operation not permitted错误。

3.所有kubernetes minion节点安装nfs工具  

    yum install rpcbind nfs-utils

* 整体测试  
使用钉盘中的wordpress.yaml文件测试，wordpress应用中mysql和wordpress均使用nfs存储。

## 常见问题及解决方案

1.kubernetes dns服务异常  
 
首先查看kubelet是否配置正确，安装dns需要在所有节点的kubelet启动参数中增加

    --cluster-dns=10.254.0.3 --cluster-domain=cluster.local
参数。
 
其次查看dns版本，确定kube2sky和kubernetes api通信的方式，老版本的（如v9版本），需要在yaml文件中指定kubernetes apiserver的地址和端口。新版本的（如v11版本），使用kubernetes默认的kubernetes service访问kubernetes。如果是新版本，请参考 *配置crt通信证书* 一节，修改crt证书生成方式。  如果是老版本，确定kubernetes的网络是否配置正确。

2.pv和pvc绑定失败  
pv和pvc匹配要检查以下几点：  
1) pv和pvc的标签是否一致。  
2) pv和pvc的大小是否满足要求，pvc的容量要求不能大于pv的容量。  
3) pv和pvc的accessModes必须相同。

3.mysql容器使用nfs启动不了
查看mysql对应Pod的日志，如果出现Operation not permitted错误，是因为nfs设置的共享目录权限不足，在共享目录设置中增加no_root_squash设置。

4.kubernetes https访问权限问题
访问Pod中服务可能会报以下错误：

    x509: cannot validate certificate for x.x.x.x because it doesn't contain any IP SANs
这个是因为没有设置或者设置的证书出错，参考 *配置crt通信证书* 重新生成证书，修改配置即可。

5.guestbook服务写数据无响应  
这个是因为guestbook要使用的angular.min.js需要翻墙才能使用，可以把js文件下载到本地，重新生成镜像。

6.cassandra服务无法访问kubernetes api  
v6版本的cassandra使用的SeedProvider有BUG，使用的默认的服务域名为

    kubernetes.default.cluster.local
正确的应该是  

    kubernetes.default.svc.cluster.local
这个只能通过重新编译源码，打包镜像解决。  
v7版本的镜像因权限问题cassandra启动脚本执行失败。没有深入研究解决方法。  
v8版本已经解决了上述问题，但是没有找到可以使用的镜像。  

7.nslookup解析正常，不能用域名访问服务  
查看主机的/etc/resolv.conf文件，如果存在类似记录则删除掉：

    options timeout:1 attempts:1 rotate


8.问题排查方法  
1) kubectl describe pod POD_NAME --namespace=NAME_SPACE查看Pod的事件及基本信息。如下载镜像失败等问题都可以从这块定位出来。  
2) kubectl logs POD_NAME --namespace=NAME_SPACE查看Pod的日志，定位服务本身的问题，具体问题具体分析。  
3) 在Pod内部访问kubernetes apiserver有两种方式。  
一种是指定apiserver的地址和端口，如果使用这种方式访问失败，比如timeout，可以从集群网络环境入手排查问题。  
另一种是使用kubernetes的默认service访问，这种访问方式使用的是https，并且依赖于集群dns服务。如果出现问题，先排查集群的dns服务是否安装正确。创建busybox Pod，执行  

    kubectl exec busybox nslookup kubernetes.default.svc.cluster.local --namespace=kube-system
    
    Server:    10.254.0.3
    Address 1: 10.254.0.3

    Name:      kubernetes.default.svc.cluster.local
    Address 1: 10.254.0.1

如果可以正确解析域名说明服务正常。

      
    
其次排查集群crt证书是否配置正确。使用命令：  

    kubectl exec frontend-0ghx0 ls /var/run/secrets/kubernetes.io/serviceaccount/
查看Pod内部证书和crt文件。 

9.kubernetes升级
centos源安装的kubernetes有很多问题，可以使用官方release的版本升级kubernetes。升级方式是下载二进制包，停止kubernetes服务，用下载的二进制包替换老的二进制包，重新启动服务即可。

 
 