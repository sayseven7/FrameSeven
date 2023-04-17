#!/bin/sh
# Author: SaySeven

alias install_nmap='apt install nmap -y'

if [ `whoami` != 'root' ];then
    printf '%s\n' 'Para rodar esse script, é necessário ser root.'
    exit 1
fi

check_sqlmap=$(which nmap)
if [ $? != 0 ]; then
    printf '%s' '[DEPENDENCIA] Nmap não está instalado; desaja instalar [y/n]? ' 
    read yeah
    if printf '%s' "${yeah}" | grep -iq '^y'; then
      install_nmap
    else
      printf '%s\n' 'Sem o Nmap, não tenho como funcionar.'
    fi
fi
unset yeah


cat <<!

  _   _      __  __      _       ____     ____   U _____ u__     __ U _____ u _   _     
 | \ |"|   U|' \/ '|uU  /"\  u U|  _"\ u / __"| u\| ___"|/\ \   /"/u\| ___"|/| \ |"|    
<|  \| |>  \| |\/| |/ \/ _ \/  \| |_) |/<\___ \/  |  _|"   \ \ / //  |  _|" <|  \| |>   
U| |\  |u   | |  | |  / ___ \   |  __/   u___) |  | |___   /\ V /_,-.| |___ U| |\  |u   
 |_| \_|    |_|  |_| /_/   \_\  |_|      |____/>> |_____| U  \_/-(_/ |_____| |_| \_|    
 ||   \\,-.<<,-,,-.   \\    >>  ||>>_     )(  (__)<<   >>   //       <<   >> ||   \\,-. 
 (_")  (_/  (./  \.) (__)  (__)(__)__)   (__)    (__) (__) (__)     (__) (__)(_")  (_/ 
                                FrameSeven 2.0 by: SaySeven :)

!

printf '%s' 'Digite a URL ou o IP do alvo: '
read alvo


printf "\
    1 - Simples scanner de portas TCP.
    2 - Simples scanner de portas UDP
    3 - Scanner mais detalhado com nomes de servições e sistema operacional
    4 - Scanner em busca de falhas web e dos serviços rodando nas portas. Obs: Demora
    5 - Scanner com Scripts padrões do Nmap
    6 - Procura Firewall\n"

printf '%s' 'Escolha uma alternativa [1/2/3/4/5/6]:' 
read op
echo "\n"

case "${op}" in
    1)
    nmap -v $alvo
    ;;
    2)
    nmap -v -sU $alvo
    ;;
    3)
    nmap -v -Pn -sV -O $alvo
    ;;
    4)
    nmap -v -Pn -sV -O --script=vuln* $alvo
    ;;
    5)
    nmap -v -Pn -sV -sS -sC $alvo
    ;;
    6)
    nmap -v -T2 -PE -sS -Pn --script=firewalk --traceroute $alvo  
esac

