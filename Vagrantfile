# Download and configure a stock VirtualBox instance of Ubuntu Raring 13.04.
# Configure it for runtime and development of cpppo applications (including
# Docker-based configurations)
Vagrant.configure("2") do |config|
  config.vm.box				= "precise64"
  config.vm.provision "shell" do |s|
    # Installs lxc-docker, and linux-image-extra-3.X.X-... for every installed kernel version
    # (which may be different than the running kernel after the upgrade! )
    # Raring requiries software-properties-common, Precise python-software-properties
    # to supply apt-add-repository
    s.inline 				= '			\
        apt-get update						\
        && apt-get install -y					\
            software-properties-common python-software-properties\
            apt-show-versions					\
        && apt-get -u -y dist-upgrade				\
        && add-apt-repository ppa:dotcloud/lxc-docker		\
        && apt-get update					\
        && apt-get install -y `apt-show-versions -a | sed -ne	\
           \'s/^\(linux-image\)-\([[:digit:]\.]\+[^[:space:]]*\).*installed$/\1-extra-\2/p\'`\
	   git python-pip lxc-docker 				\
        && sudo pip install cpppo				\
        && git clone http://github.com/pjkundert/cpppo src/cpppo\
	'
  end
  config.vm.network "forwarded_port",	   guest: 80, host: 8080
  config.vm.synced_folder		   ".", "/vagrant"
  config.vm.provider "vmware_fusion" do |v|
    v.gui 				= true
    v.vmx["memsize"]			= "2048"
    v.vmx["numvcpus"]			= "2"
  end
  config.vm.provider "virtualbox" do |v|
    v.gui 				= true
  end
end
