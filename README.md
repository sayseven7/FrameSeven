# FrameSeven
# Autor:SaySeven

				 (`-').-> (`-')  _         _  (`-') 
				 (OO )__  ( OO).-/  <-.    \-.(OO ) 
				,--. ,'-'(,------.,--. )   _.'    \ 
				|  | |  | |  .---'|  (`-')(_...--'' 
				|  `-'  |(|  '--. |  |OO )|  |_.' | 
				|  .-.  | |  .--'(|  '__ ||  .___.' 
				|  | |  | |  `---.|     |'|  |      
				`--' `--' `------'`-----' `--'  
							FrameSeven 1.0 Version 
		Usage: FrameSeven [options]
		Options:
			-h, --help		show this help message and exit
			-u  www.site.com, --url=www.google.com
							Lista diretorios no site
			-d	admin, --admin=admin
							Procura o admin
			-l				Procura links
			--sp			Scan de portas
			--ssmpt			Enumerar smtp
			--bftp			Brutar ftp
			--bssh			Brutar ssh	
      		--csqli			Checar SQLI
			--sqls          	Sqlmap_Seven, explorar sqli
 
Ex: python FrameSeven.py -u -d -l --bssh admin www.site.com


Ex: python FrameSeven.py --csqli http://www.site.com/parametro.php?artist=1 www.site.com


Ex: python FrameSeven.py --sqls www.site.com  --> O programa irar pedir a url vulneravel, você especificar por exempo: http://www.site.com/parametro.php?artist=1

OBS: Cheque se sua variavel de ambiente está como root, echo $USER

OBS IMPORTANTE: Instale as dependencias --> pip install -r dependencias.txt

OBS IMPORTANTE: Instale o Git-Lfs --> apt install git-lfs
