#01/06/2022
# UPDATE 01/09/2023
#By @ChumoGH|Plus

function chekKEY {
[[ -z ${IP} ]] && IP=$(cat < /bin/ejecutar/IPcgh)
[[ -z ${IP} ]] && IP=$(wget -qO- ifconfig.me)
Key="$(cat /etc/cghkey)"
_double=$(curl -sSL "https://www.dropbox.com/s/5hr0wv1imo35j1e/Control-Bot.txt")
local IiP="$(cat < /usr/bin/vendor_code)"
[[ -e /file ]] && _double=$(cat < /file) ||  {
wget -q -O /file https://www.dropbox.com/s/5hr0wv1imo35j1e/Control-Bot.txt
_double=$(cat < /file)
}
_check2="$(echo -e "$_double" | grep ${IiP})"
[[ ! -e /etc/folteto ]] && {
wget --no-check-certificate -O /etc/folteto $IiP:81/ChumoGH/checkIP.log
cheklist="$(cat /etc/folteto)"
echo -e "$(echo -e "$cheklist" | grep ${IP})" > /etc/folteto
}
[[ -z ${_check2} ]] && {
exit && exit
}
}

[[ -d /etc/ADMcgh ]] || mkdir /etc/ADMcgh
[[ -d /etc/ADMcgh/bin ]] || mkdir /etc/ADMcgh/bin
[[ -e /bin/ejecutar/msg ]] && source /bin/ejecutar/msg || source <(curl -sSL https://raw.githubusercontent.com/ChumoGH/ADMcgh/main/Plugins/system/styles.cpp)

function roleta() {
work=$1
	sleep 1
	helice() {
		${work} >/dev/null 2>&1 &
		tput civis
		while [ -d /proc/$! ]; do
			for i in / - \\ \|; do
				sleep .1
				echo -ne "\e[1D$i"
			done
		done
		tput cnorm
	}
	echo -ne "\033[1;37mBuscando Binario \033[1;32mBadVPN \033[1;37me \033[1;32mSWAP\033[1;32m.\033[1;33m.\033[1;31m. \033[1;33m"
	helice
	echo -e "\e[1DOk"
}



BadVPN () {
pid_badvpn=$(ps x | grep badvpn | grep -v grep | awk '{print $1}')
unset bot_ini
if [ "$pid_badvpn" = "" ]; then
msg -ama " FUNCION REDISEÑADA HABILITARA EL PUERTO 7300 en BADVPN-UDP"
msg -ama "  ADICIONAL APERTURARENOS EL 7200 PARA UN DUAL CHANNEL"
msg -ama "        PROCURA ALTERNAR LOS PUERTOS EN LAS APPS"
msg -ama "   PARA UNA EXPERIENCIA LIGERA Y SIN CORTES DE LLAMADAS"
msg -bar3
roleta 'apt-get install toilet -y'
    if [[ ! -e /bin/badvpn-udpgw ]]; then
	echo -ne "	    DESCARGANDO BINARIO UDP V2.."
  [[ $(uname -m 2> /dev/null) != x86_64 ]] && {
  #chekKEY &> /dev/null 2>&1
  #if wget -O /bin/badvpn-udpgw https://github.com/ChumoGH/ScriptCGH/raw/main/HTools/BadVPN/badvpn-udpgw &>/dev/null ; then
  if wget -O /bin/badvpn-udpgw https://raw.githubusercontent.com/ChumoGH/ADMcgh/main/BINARIOS/aarch64/badvpn-udpgw &>/dev/null ; then
  chmod 777 /bin/badvpn-udpgw
  msg -verd "[OK]"
  else
  msg -verm "[fail]"
  msg -bar3
  msg -ama "No se pudo descargar el binario"
  msg -verm "Instalacion canselada"
  read -p "ENTER PARA CONTINUAR"
  exit 0
  fi
  } || {
  #chekKEY &> /dev/null 2>&1
  #if wget -O /bin/badvpn-udpgw https://github.com/ChumoGH/ScriptCGH/raw/main/HTools/BadVPN/badvpn-udpgw-plus &>/dev/null ; then
  if wget -O /bin/badvpn-udpgw https://raw.githubusercontent.com/ChumoGH/ADMcgh/main/BINARIOS/x86_64/badvpn-udpgw &>/dev/null ; then
  chmod 777 /bin/badvpn-udpgw
  msg -verd "[OK]"
  else
  msg -verm "[fail]"
  msg -bar3
  msg -ama "No se pudo descargar el binario"
  msg -verm "Instalacion canselada"
  read -p "ENTER PARA CONTINUAR"
  exit 0
  fi
  }
	msg -ama "                   ACTIVANDO BADVPN Plus"
	msg -bar3
	tput cuu1 && tput dl1
	tput cuu1 && tput dl1
    fi
    (
	screen -dmS badvpn $(which badvpn-udpgw) --listen-addr 127.0.0.1:7300 --max-clients 1000 --max-connections-for-client 10 #--client-socket-sndbuf 10000
	screen -dmS badUDP72 $(which badvpn-udpgw) --listen-addr 127.0.0.1:7200 --max-clients 1000 --max-connections-for-client 10 #--client-socket-sndbuf 10000
#	screen -dmS badvpn $(which badvpn-udpgw) --listen-addr 127.0.0.1:7300 --max-clients 1000 --max-connections-for-client 10
#	screen -dmS badUDP72 $(which badvpn-udpgw) --listen-addr 127.0.0.1:7200 --max-clients 1000 --max-connections-for-client 10
	) || msg -ama "                Error al Activar BadVPN"
	sleep 2s
	msg -bar3
    [[ ! -z $(ps x | grep badvpn | grep -v grep ) ]] && {
	msg -verd "                  ACTIVADO CON EXITO"
		msg -bar3
	echo -e "  PREGUNTA PREVIA POR 15 SEGUNDOS !!!"
	msg -bar3
	read -t 15 -p " $(echo -e "\033[1;97m Poner en linea despues de un reinicio [s/n]: ")" -e -i "s" bot_ini
	msg -bar3
	tput cuu1 && tput dl1
	tput cuu1 && tput dl1
	tput cuu1 && tput dl1
	tput cuu1 && tput dl1
	tput cuu1 && tput dl1
		[[ $bot_ini = @(s|S|y|Y) ]] && {
	[[ $(grep -wc "badvpn" /bin/autoboot) = '0' ]] && {
						echo -e " REACTICADOR DE BADVPN ACTIVADO !! " && sleep 2s
						tput cuu1 && tput dl1
						echo -e "netstat -tlpn | grep -w 7300 > /dev/null || {  screen -r -S 'badvpn' -X quit;  screen -dmS badvpn $(which badvpn-udpgw) --listen-addr 127.0.0.1:7300 --max-clients 1000 ; }" >>/bin/autoboot
						echo -e "netstat -tlpn | grep -w 7200 > /dev/null || {  screen -r -S 'badUDP72' -X quit;  screen -dmS badUDP72 $(which badvpn-udpgw) --listen-addr 127.0.0.1:7200 --max-clients 1000 ; }" >>/bin/autoboot
					} || {
						sed -i '/badvpn/d' /bin/autoboot
						echo -e " AUTOREINICIO EN INACTIVIDAD REACTIVADO !! " && sleep 2s
						tput cuu1 && tput dl1
						echo -e "netstat -tlpn | grep -w 7300 > /dev/null || {  screen -r -S 'badvpn' -X quit;  screen -dmS badvpn $(which badvpn-udpgw) --listen-addr 127.0.0.1:7300 --max-clients 1000 --max-connections-for-client 10; }" >>/bin/autoboot
						echo -e "netstat -tlpn | grep -w 7200 > /dev/null || {  screen -r -S 'badUDP72' -X quit;  screen -dmS badUDP72 $(which badvpn-udpgw) --listen-addr 127.0.0.1:7200 --max-clients 1000 --max-connections-for-client 10; }" >>/bin/autoboot
					}
	#-------------------------
} ||  sed -i '/badvpn-udpgw/d' /bin/autoboot
}

else
clear&&clear
msg -bar3
msg -ama "      Administrador BadVPN UDP | @ChumoGH•Plus"
msg -bar3
menu_func "AÑADIR 1+ PUERTO BadVPN $_pid" "$(msg -verm2 "Detener BadVPN")" #"$(msg -ama "Reiniciar BadVPN")"
 echo -ne "$(msg -verd " [0]") $(msg -verm2 "=>>") " && msg -bra "\033[1;41m Volver "
  msg -bar3
  opcion=$(selection_fun 2)
  case $opcion in
  1)
msg -bar3
msg -ama " FUNCION EXPERIMENTAL AGREGARA PUERTO en BADVPN-UDP"
#msg -ama "  ADICIONAL APERTURARENOS EL 7200 PARA UN DUAL CHANNEL"
#msg -ama "        MAXIMO DE 100 CONEXIONES POR CLIENTE"
msg -bar3
read -p " DIJITA TU PUERTO CUSTOM PARA BADVPN :" -e -i "7100" port
echo -e " VERIFICANDO BADVPN "
msg -bar3
#screen -dmS badvpn$port /bin/badvpn-udpgw --listen-addr 127.0.0.1:${port} --max-clients 10000 --max-connections-for-client 10000 --client-socket-sndbuf 10000 && msg -ama "               BadVPN ACTIVADA CON EXITO"  || msg -ama "                Error al Activar BadVPN"
screen -dmS badvpn$port /bin/badvpn-udpgw --listen-addr 127.0.0.1:${port} --max-clients 1000 --max-connections-for-client 10 && msg -ama "               BadVPN ACTIVADA CON EXITO"  || msg -ama "                Error al Activar BadVPN"
echo -e "netstat -tlpn | grep -w ${port} > /dev/null || {  screen -r -S 'badvpn'$port -X quit;  screen -dmS badvpn $(which badvpn-udpgw) --listen-addr 127.0.0.1:${port} --max-clients 1000 --max-connections-for-client 10; }" >>/bin/autoboot
msg -bar3
return
  ;;
  2)
msg -ama "                DESACTIVANDO BADVPN"
    msg -bar3
	kill -9 $(ps x | grep badvpn | grep -v grep | awk '{print $1'}) > /dev/null 2>&1
    killall badvpn-udpgw > /dev/null 2>&1
	sed -i '/badvpn/d' /bin/autoboot
	echo -e " AUTOREINICIO EN INACTIVIDAD ELIMINADO !! " && sleep 2s
	tput cuu1 && tput dl1
    [[ ! "$(ps x | grep badvpn | grep -v grep | awk '{print $1}')" ]] && msg -ama "                APAGADO EXITOSAMENTE \n" || msg -verm "                ERROR AL DETENER BadVPN!! \n"
    unset pid_badvpn
	msg -bar3
return
  ;;
  3)exit;;
  0)exit;;
 esac


fi
unset pid_badvpn
}

BadVPN

msg -bar3
clear&&clear
msg -bar3
toilet -f pagga "ChumoGH-UDP" | lolcat
msg -bar3
print_center -verd  "ACTIVADO CON EXITO"
msg -bar3


return
