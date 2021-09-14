domain=$1
wordlist="/home/ap/need/wordlist.txt"
reso="/home/ap/need/reso.txt"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

function red {
    printf "${RED}$@${NC}\n"
}

function green {
    printf "${GREEN}$@${NC}\n"
}

function yellow {
    printf "${YELLOW}$@${NC}\n"
}

install() {
	mkdir ~/tools
	GO111MODULE=on go install github.com/projectdiscovery/httpx/cmd/httpx@latest
	GO111MODULE=on go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
    GO111MODULE=on go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
    GO111MODULE=on go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    GO111MODULE=on go install github.com/tomnomnom/assetfinder@latest
    GO111MODULE=on go install github.com/OWASP/Amass/v3/...@latest
    GO111MODULE=on go install github.com/tomnomnom/waybackurls@latest
    GO111MODULE=on go install github.com/ffuf/ffuf@latest
    GO111MODULE=on go install github.com/tomnomnom/gf@latesthttp
    GO111MODULE=on go install github.com/tomnomnom/unfurl@latest
    GO111MODULE=on go install github.com/ffuf/ffuf@latest
    #echo 'source ~/go/pkg/mod/github.com/tomnomnom/gf@v0.0.0-20200618134122-dcd4c361f9f5/gf-completion.bash' >> ~/.bashrc
    #source ~/.bashrc
    
    cd ~/tools
    git clone https://github.com/1ndianl33t/Gf-Patterns
    mkdir  ~/.gf
    mv Gf-Patterns/*.json ~/.gf
    
    sudo apt-get --assume-yes install git make gcc
	git clone https://github.com/robertdavidgraham/masscan
	cd masscan
	make
	sudo make install

    
    git clone https://github.com/blechschmidt/massdns.git
    cd massdns && make && sudo make install
    

    wget https://github.com/findomain/findomain/releases/latest/download/findomain-linux
    chmod +x findomain-linux
    sudo cp findomain-linux /usr/local/bin
    sudo apt install whatweb

}


yellow "▄▄▄▄· ▄• ▄▌ ▄▄ •     ▄▄▄▄·       ▄• ▄▌ ▐ ▄ ▄▄▄▄▄ ▄· ▄▌  "    
yellow "▐█ ▀█▪█▪██▌▐█ ▀ ▪    ▐█ ▀█▪▪     █▪██▌•█▌▐█•██  ▐█▪██▌   "   
yellow "▐█▀▀█▄█▌▐█▌▄█ ▀█▄    ▐█▀▀█▄ ▄█▀▄ █▌▐█▌▐█▐▐▌ ▐█.▪▐█▌▐█▪    "  
yellow "██▄▪▐█▐█▄█▌▐█▄▪▐█    ██▄▪▐█▐█▌.▐▌▐█▄█▌██▐█▌ ▐█▌· ▐█▀·.     " 
yellow "·▀▀▀▀  ▀▀▀ ·▀▀▀▀     ·▀▀▀▀  ▀█▄▀▪ ▀▀▀ ▀▀ █▪ ▀▀▀   ▀ •       "
yellow " ▄▄▄· ▄• ▄▌▄▄▄▄▄      • ▌ ▄ ·.  ▄▄▄· ▄▄▄▄▄▪         ▐ ▄     "
yellow "▐█ ▀█ █▪██▌•██  ▪     ·██ ▐███▪▐█ ▀█ •██  ██ ▪     •█▌▐█    "
yellow "▄█▀▀█ █▌▐█▌ ▐█.▪ ▄█▀▄ ▐█ ▌▐▌▐█·▄█▀▀█  ▐█.▪▐█· ▄█▀▄ ▐█▐▐▌    "
yellow "▐█ ▪▐▌▐█▄█▌ ▐█▌·▐█▌.▐▌██ ██▌▐█▌▐█ ▪▐▌ ▐█▌·▐█▌▐█▌.▐▌██▐█▌    "
yellow " ▀  ▀  ▀▀▀  ▀▀▀  ▀█▄▀▪▀▀  █▪▀▀▀ ▀  ▀  ▀▀▀ ▀▀▀ ▀█▄▀▪▀▀ █▪    "



 if ! command -v whatweb &> /dev/null
then
    install
fi
                                                        



red "STARTING DOMAIN ENUMARATION"
domain_enum(){

mkdir -p $domain $domain/sources $domain/Recon  $domain/Recon/nuclei $domain/Recon/waybackurls  $domain/Recon/gf $domain/Recon/wordlist $domain/Recon/massscan
whatweb $domain > $domain/sources/server.txt
subfinder -d $domain -o $domain/sources/subfinder.txt
cat $domain/sources/subfinder.txt | waybackurls | sort | uniq > $domain/sources/urls.txt
findomain -t  $domain  --quiet | tee $domain/sources/findodmain.txt
assetfinder -subs-only $domain | tee $domain/sources/assetfinder.txt
amass enum  -passive -d $domain -o $domain/sources/passive.txt
shuffledns  -d $domain -w $wordlist -r $reso -o $domain/sources/shuffledns.txt
./googledorks.sh  $domain > $domain/sources/dorks.txt
cat $domain/sources/*.txt > $domain/sources/all.txt

}
domain_enum

red "STARTING TO RESOLVE DOMAINS"
resolving_domains(){
#resolve doamin using shuffle_dns
shuffledns -d $domain -list $domain/sources/all.txt -o $domain/domains.txt  -r $reso
}
resolving_domains

red "STARTING HTTP CHECK"
http_prob(){
#checking http /https
cat $domain/domains.txt | httpx -threads 200 -o $domain/Recon/httpx.txt
}
http_prob

red "STARTING VULN CHECK"
scanner(){

#cat $domain/Recon/httpx.txt |nuclei -t /home/ap/nuclei-templates/cves/ -c 50 -o $domain/Recon/nuclei/cves.txt
cat $domain/Recon/httpx.txt |nuclei -t $nuc/files/ -c 50 -o $domain/Recon/nuclei/files.txt -tags cve -severity critical,high,medium
#cat $domain/Recon/httpx.txt |nuclei -t $nuc/vulnerabilities/ -c 50 -o $domain/Recon/nuclei/vulnerabilites.txt
#cat $domain/Recon/httpx.txt |nuclei -t $nuc/technologies/ -c 50 -o $domain/Recon/nuclei/technologies.txt

}
scanner

red "STARTING ARCHIVE URLS CHECK"
wbs(){

cat $domain/Recon/httpx.txt | waybackurls | tee $domain/Recon/waybackurls/waybackurls.txt
cat $domain/Recon/waybackurls/waybackurls.txt | egrep -v  "\.woff|\.ttf|\.eot|\.png|\.jpeg|\.jpg|\.svg|\.css|\.ico" |sed 's/:80//g;s/:443//g' | sort -u > $domain/Recon/waybackurls/wbresolve.txt


}
wbs

red "STARTING FUZZING"
ff(){

ffuf -c -u "FUZZ" -w  $domain/Recon/waybackurls/wbresolve.txt -of csv -o $domain/Recon/waybackurls/temp.txt
cat  $domain/Recon/waybackurls/temp.txt | grep http |awk -F '{print $3}' |tee $domain/Recon/waybackurls/valid.txt
rm -rf $domain/Recon/waybackurls/temp.txt


}
ff

red "STARTING XSS, SSRF SQLI CHECKS"
gfp(){

gf xss  $domain/Recon/waybackurls/valid.txt | tee  $domain/Recon/gf/gf.txt
gf sqli $domain/Recon/waybackurls/valid.txt | tee  $domain/Recon/gf/sqli.txt
gf ssrf $domain/Recon/waybackurls/valid.txt | tee  $domain/Recon/gf/ssrf.txt
gf ssti $domain/Recon/waybackurls/valid.txt | tee  $domain/Recon/gf/ssti.txt
}
gfp


cw(){
cat $domain/Recon/waybackurls/valid.txt | unfurl -unique paths > $domain/Recon/wordlist/path.txt
cat $domain/Recon/waybackurls/valid.txt | unfurl -unique keys > $domain/Recon/wordlist/params.txt
}
cw

red "STARTING SCANNING"
resolving(){

massdns -r $reso  -t AAAA  -w $domain/Recon/massscan/results.txt   $domain/domains.txt
cat $domain/Recon/massscan/results.txt |awk -F '{print $1}' |tee $domain/Recon/massscan/tmp.txt
gf ip $domain/Recon/massscan/tmp.txt |tee $domain/Recon/massscan/ip.txt
rm -rf $domain/Recon/massscan/tmp.txt

}
resolving
