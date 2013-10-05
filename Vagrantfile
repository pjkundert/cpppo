Vagrant.configure("2") do |config|
  config.vm.box				= "raring"
  config.vm.box_url			= "http://cloud-images.ubuntu.com/raring/current/raring-server-cloudimg-vagrant-amd64-disk1.box"
  config.vm.provision "shell" do |s|
    # Installs lxc-docker, and linux-image-extra-3.X.X-... for every installed kernel version
    # (which may be different than the running kernel after the upgrade! )
    s.inline 				= '\
        apt-get update						\
        && apt-get install -y					\
            software-properties-common apt-show-versions	\
        && apt-get -u -y dist-upgrade				\
        && add-apt-repository ppa:dotcloud/lxc-docker		\
        && apt-get update					\
        && echo `apt-show-versions -a				\
            | sed -ne \'/linux-image-[[:digit:]\.]\+.*installed/ p\'`\
        && apt-get install -y lxc-docker `apt-show-versions -a	\
            | sed -ne \'s/^\(linux-image\)-\([[:digit:]\.]\+[^[:space:]]*\).*installed$/\1-extra-\2/p\'`'
  end
  config.vm.network "forwarded_port",	   guest: 80, host: 8080
  config.vm.synced_folder		   ".", "/vagrant"
  config.vm.provider "vmware_fusion" do |v|
    v.vmx["memsize"]			= "2048"
    v.vmx["numvcpus"]			= "2"
  end
  config.vm.provider "virtualbox" do |v|
    v.gui 				= true
  end
end
