#!/bin/bash
# ==============================================================================
# De-obfuscated SlowDNS Management Script
# Original Author: ChumoGH (implied by references)
# De-obfuscated by: Jules
#
# Description:
# This script manages a SlowDNS tunnel server. It handles:
# - Installation of binaries (dns-server)
# - Key generation and management (server.key, server.pub)
# - IPTables firewall configuration for traffic redirection
# - Service management (start, stop, restart, dual-instance)
# - Authorization checking (chekKEY)
# ==============================================================================

clear
rm -rf /tmp/* &>/dev/null
# script_name=$(basename "$0")
# rm -f $(pwd)/${script_name} &>/dev/null

# ------------------------------------------------------------------------------
# Directory Setup
# ------------------------------------------------------------------------------
# Ensures necessary configuration directories exist.
[[ ! -d /etc/adm-lite/slow/ ]] && mkdir /etc/adm-lite/slow
ADM_slow="/etc/adm-lite/slow/dnsi" && [[ ! -d ${ADM_slow} ]] && mkdir ${ADM_slow}
ADM_inst='/bin'

# Load or define key path
Key="$(cat < /etc/cghkey)" && _Key='/etc/cghkey'
[[ -d /etc/ADMcgh ]] || mkdir /etc/ADMcgh
[[ -d /etc/ADMcgh/bin ]] || mkdir /etc/ADMcgh/bin

# Source external styling/message functions. If missing, download them.
[[ -e /bin/ejecutar/msg ]] && source /bin/ejecutar/msg || source <(curl -sSL https://raw.githubusercontent.com/ChumoGH/ADMcgh/main/Plugins/system/styles.cpp)

#FELICIDADES, NUNCA DEJES DE APRENDER (CONGRATULATIONS, NEVER STOP LEARNING)
_Key='/etc/cghkey'

# ------------------------------------------------------------------------------
# Network Configuration (IPTables Rules)
# ------------------------------------------------------------------------------
# PRIMARY INSTANCE RULES (Port 5300)
# rule1: Allows incoming UDP traffic on port 5300 (where the SlowDNS server listens).
rule1="-I INPUT -p udp --dport 5300 -j ACCEPT"
# rule2: Redirects all incoming UDP traffic on standard DNS port 53 to port 5300.
#        This allows the server to receive DNS requests on the standard port but handle them on 5300.
rule2="-t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5300"

# SECONDARY INSTANCE RULES (Port 5400 - "Dual Port" feature)
# rule1SEC: Allows incoming UDP traffic on port 5400.
rule1SEC="-I INPUT -p udp --dport 5400 -j ACCEPT"
# rule2SEC: Redirects all incoming UDP traffic on standard DNS port 53 to port 5400.
#           Note: This seems to conflict with rule2 if both are active simultaneously on the same PREROUTING chain
#           without specific source filtering. It might be intended for alternating or specific use cases.
rule2SEC="-t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5400"

# ------------------------------------------------------------------------------
# Key Management Functions
# ------------------------------------------------------------------------------

# Function: call_key_fija
# Downloads a pre-defined (fixed) private/public key pair from the GitHub repository.
# Useful for restoring a known configuration.
call_key_fija () {
  echo -ne " CHECK SERVER 1 "
  if wget --no-check-certificate -t3 -T3 -O ${ADM_slow}/server.key https://raw.githubusercontent.com/ChumoGH/ADMcgh/main/Plugins/Extras/server.key &>/dev/null ; then
    chmod +x ${ADM_slow}/server.key
    msg -verd "[OK]"
  else
    msg -verm "[fail]"
    msg -bar3
    msg -ama "No se pudo descargar el key"
    read -p "ENTER PARA CONTINUAR"
    rm -f ${ADM_slow}/pidfile
    exit 0
  fi

  echo -ne " CHECK SERVER 2 "
  if wget --no-check-certificate -t3 -T3 -O ${ADM_slow}/server.pub https://raw.githubusercontent.com/ChumoGH/ADMcgh/main/Plugins/Extras/server.pub &>/dev/null ; then
    chmod +x ${ADM_slow}/server.pub
    msg -verd "[OK]"
  else
    msg -verm "[fail]"
    msg -bar3
    msg -ama "No se pudo descargar el key"
    read -p "ENTER PARA CONTINUAR"
    rm -f ${ADM_slow}/pidfile
    exit 0
  fi
}

# Function: create_random_text_file
# Prompts the user to manually paste their Public and Private keys.
create_random_text_file () {
  msg -bar3
  print_center -verd "  NOTA IMPORTANTE !!! \n RECUERDA INGRESAR \n CLAVE PUBLICA (.PUB )\n CLAVE PRIVADA ( .KEY ) \n AMBAS COMPATIBLES "
  msg -bar3
  while true; do
      echo -e "INGRESA TU CLAVE .PUB EN FORMATO BASE64"
      read -p " CODE PUB :" _pub

      # Verify input is not empty
      if [ -n "$_pub" ]; then
          echo $_pub > ${ADM_slow}/server.pub
          echo "La clave pública se ha guardado en ${ADM_slow}/server.pub"
          break
      else
          echo "La entrada no puede estar vacía. Por favor, intenta de nuevo."
      fi
  done

  while true; do
      echo -e "INGRESA TU CLAVE .KEY EN FORMATO .KEY"
      read -p " CODE KEY :" _key

      # Verify input is not empty
      if [ -n "$_key" ]; then
          echo $_key > ${ADM_slow}/server.key
          echo "La clave privada se ha guardado en ${ADM_slow}/server.key"
          break
      else
          echo "La entrada no puede estar vacía. Por favor, intenta de nuevo."
      fi
  done
}

# Function: show_menu
# Displays the Key Selection Menu.
# Options:
# 1. Use Fixed Key (Download from repo)
# 2. Input Key manually
# 3. Generate Random Key (using dns-server binary)
# 4. Use Existing Key (if present)
# 5. Cancel
show_menu() {
  while true; do
    clear&&clear
    tittle
    print_center -verd "  NOTA IMPORTANTE !!! \n LA KEY FIJA, SIEMPRE SERA LA MISMA \n A EXEPCION DEL NameServer\n SU PublicKey (KEY) SERA LA MISMA AUNQUE REINSTALES "
    msg -bar3
    print_center -verm2 "  ESTA OPCION NO SALDRA MAS \n LEE DETENIDAMENTE ANTES DE SALIR!! "
    msg -bar3
    menu_func "USAR KEY FIJA ( ADMcgh )" "$(msg -ama "CARGAR TU PUB/KEY")" "$(msg -verd "GENERAR KEY RAMDOM")" "$(msg -ama "USAR EXISTENTE")" "$(msg -verm "CANCELAR")"
    msg -bar3
    read -p "Ingrese su opción: " OPTION

    case $OPTION in
        1)
            call_key_fija
            touch ${ADM_slow}/pidfile
            ex_key='y'
            break
            ;;
        2)
            create_random_text_file
            touch ${ADM_slow}/pidfile
            ex_key='y'
            break
            ;;
        3)
            # Generates a new key pair using the dns-server binary
            ${ADM_inst}/dns-server -gen-key -privkey-file ${ADM_slow}/server.key -pubkey-file ${ADM_slow}/server.pub &>/dev/null
            touch ${ADM_slow}/pidfile
            unset ex_key
            break
            ;;
        4)
            [[ -e ${ADM_slow}/server.pub ]] && break || echo -e " NO EXISTE KEY PUB "
            touch ${ADM_slow}/pidfile
        ;;
        5)
            rm -f ${ADM_slow}/pidfile
            exit 0
            break
        ;;
        *)
            echo "Opción no válida. Intente de nuevo."
            ;;
    esac
  done
  echo -e " $(msg -ama "KEY.PUB:") $(msg -verd "$(cat ${ADM_slow}/server.pub)")"
}

clear

# ------------------------------------------------------------------------------
# License/Authorization Check (chekKEY)
# ------------------------------------------------------------------------------
# This function verifies if the user/IP is authorized to use the script.
# 1. Gets the Public IP (IP).
# 2. Gets the local machine ID/Vendor Code (IiP).
# 3. Downloads an authorized list (Control-Bot.txt) from Dropbox.
# 4. Greps the authorized list for the machine ID/IP.
# 5. If not found (empty string), it displays "BotGEN NO AUTORIZADO" and exits.
# 6. If found, it echoes the result.
function chekKEY {
  [[ -z ${IP} ]] && IP=$(wget -qO- ifconfig.me)
  [[ -z ${IP} ]] && IP=$(cat < /bin/ejecutar/IPcgh)
  Key="$(cat /etc/cghkey)"
  [[ -z ${IiP} ]] && IiP=$(cat < /usr/bin/vendor_code)

  # Check if the list file exists, if not download it
  [[ -e /file ]] && _double=$(cat < /file) ||  {
    wget -q -O /file https://www.dropbox.com/s/5hr0wv1imo35j1e/Control-Bot.txt
    _double=$(cat < /file)
  }

  # Search for the Machine ID/IP in the list
  _check2="$(echo -e "$_double" | grep ${IiP})"

  # If grep returns empty, unauthorized.
  [[ -z ${_check2} ]] && {
    mss_='\n BotGEN NO AUTORIZADO POR @ChumoGH '
    msg -bar3
    echo -e "$mss_"
    msg -bar3
    read -p " PRESS TO ENTER TO CONTINUED"
    exit && exit
  } || echo "${_check2}" /etc/chekKEY
}

# ------------------------------------------------------------------------------
# Helper Functions
# ------------------------------------------------------------------------------

# Function: rule_exists
# Checks if an iptables rule already exists in a specific table.
rule_exists() {
    local table=$1
    local rule=$2

    if iptables -t $table -C $rule &> /dev/null; then
        return 0
    else
        return 1
    fi
}

# Function: delete_rule
# Deletes an iptables rule if it exists.
# Converts -I (Insert) to -D (Delete) for the command.
delete_rule() {
    local table=$1
    local rule=$2

    # Replace -I with -D
    local delete_rule=$(echo $rule | sed 's/-I /-D /')

    if rule_exists $table "$rule"; then
        iptables $delete_rule
        print_center -verd " REGLAS ELIMINADAS "
    fi
}


# Function: info
# Displays current configuration info (Nameserver, Public Key, IP).
info(){
  clear&&clear
  nodata(){
    msg -bar3
    msg -ama "        !SIN INFORMACION SLOWDNS!"
    read -p "ENTER PARA CONTINUAR"
    exit 0
  }

  # Check if config files exist
  if [[ -e  ${ADM_slow}/domain_ns ]]; then
    local ns=$(cat ${ADM_slow}/domain_ns)
    if [[ -z "$ns" ]]; then nodata; fi
  else
    nodata
  fi

  if [[ -e ${ADM_slow}/server.pub ]]; then
    local key=$(cat ${ADM_slow}/server.pub)
    if [[ -z "$key" ]]; then nodata; fi
  else
    nodata
  fi

  if [[ -e ${ADM_slow}/server.key ]]; then
    local _key=$(cat ${ADM_slow}/server.key)
    if [[ -z "$_key" ]]; then nodata; fi
  else
    nodata
  fi

  msg -bar3
  print_center -verd "  NOTA IMPORTANTE !!! \n AQUI ESTA SU INFORMACION DE CONEXION \n SU NameServer (NS )\n SU PublicKey (KEY) "
  msg -bar3
  print_center -ama " SU IP PUBLICA/IP-DNS "
  print_center -verd "$(cat < /bin/ejecutar/IPcgh)"
  msg -bar3
  print_center -ama " NameServer ( NS ) "
  print_center -verd "${ns}"
  msg -bar3
  print_center -ama " Public Key ( Pubkey ) "
  print_center -verd "${key}"
  msg -bar3
  print_center -verm2 "   ADVERTENCIA !!!"
  print_center -ama " ESTE KEY SOLO ES PARA CONEXION BACK \n GUARDELA POR SI CREO UNA LLAVE RAMDOM "
  msg -bar3
  print_center "${_key}"
  msg -bar3
  read -p " ENTER PARA CONTINUAR"
}

# Function: drop_port
# Scans for open ports to avoid conflicts or help user choose a port.
drop_port(){
  local portasVAR=$(lsof -V -i tcp -P -n | grep -v "ESTABLISHED" |grep -v "COMMAND" | grep "LISTEN")
  portasVAR+=$(lsof -V -i UDP -P -n | grep -v "ESTABLISHED" |grep -v "COMMAND"|grep -E 'openvpn|dns-serve|udpServer|hysteria|UDP-Custo|Hysteria2|ZipVPN')
  local NOREPEAT
  local reQ
  local Port
  unset DPB
  while read port; do
    reQ=$(echo ${port}|awk '{print $1}')
    Port=$(echo {$port} | awk '{print $9}' | awk -F ":" '{print $2}')
    [[ $(echo -e $NOREPEAT|grep -w "$Port") ]] && continue
    NOREPEAT+="$Port\n"
    case ${reQ} in
      sshd|dropbear|stunnel4|stunnel|trojan|v2ray|xray|python|python3|openvpn*|node|squid|squid3|sslh|snell-ser|ss-server|obfs-serv|trojan-go)DPB+=" $reQ:$Port";;
      *)continue;;
    esac
  done <<< "${portasVAR}"
}

# Function: ini_slow
# Main installation and startup logic.
ini_slow(){
  msg -bra "INSTALADOR SLOWDNS"
  drop_port
  n=1
  for i in $DPB; do
    local proto=$(echo $i|awk -F ":" '{print $1}')
    local proto2=$(printf '%-12s' "$proto")
    local port=$(echo $i|awk -F ":" '{print $2}')
    echo -e " $(msg -verd "[$n]") $(msg -verm2 ">") $(msg -ama " $(echo -e " ${flech} $proto2 "| tr [:lower:] [:upper:])")$(msg -azu "$port")"
    local drop[$n]=$port
    local dPROT[$n]=$proto2
    local num_opc="$n"
    let n++
  done
  msg -bar3
  opc=$(selection_fun $num_opc)

  # Save selected port and protocol
  echo "${drop[$opc]}" > ${ADM_slow}/puerto
  echo "${dPROT[$opc]}" > ${ADM_slow}/protc
  local PORT=$(cat ${ADM_slow}/puerto)
  local PRT=$(cat ${ADM_slow}/protc)
  msg -bra " INSTALADOR SLOWDNS "
  msg -bar3
  echo -e " $(msg -ama "Redireccion SlowDns:") $(msg -verd "$(echo -e "${PRT}" | tr [:lower:] [:upper:])") : $(msg -verd "$PORT") $(msg -ama " -> ") $(msg -verd "5300")"
  msg -bar3

  # Handle NameServer (NS) configuration
  [[ -e /dominio_NS.txt && ! -e ${ADM_slow}/domain_ns ]] && cp /dominio_NS.txt ${ADM_slow}/domain_ns
  [[ -e ${ADM_slow}/domain_ns ]] && NS1=$(cat < ${ADM_slow}/domain_ns) || unset NS1 NS
  unset NS
  [[ -z $NS1 ]] && {
    while [[ -z $NS ]]; do
      echo -ne "\e[1;31m TU DOMINIO NS \e[1;37m: "
      read NS
      tput cuu1 && tput dl1
    done
  } || {
    echo -e "\e[1;31m      TIENES UN DOMINIO NS YA REGISTRADO \e[1;37m "
    echo -e "\e[1;32m   TU NS ES : ${NS1} \e[1;37m "
    echo -e "  SI QUIERES UTILIZARLO, SOLO PRESIONA ENTER "
    echo -e "       CASO CONTRARIO DIJITA TU NUEVO NS "
    msg -bar3
    echo -ne "\e[1;31m TU DOMINIO NS \e[1;37m: "
    read NS
    [[ -z $NS ]] && NS="${NS1}"
    tput cuu1 && tput dl1
    echo "$NS" > ${ADM_slow}/domain_ns
  }
  echo "$NS" > ${ADM_slow}/domain_ns
  echo -e " $(msg -ama "NAME SERVER:") $(msg -verd "$NS")"
  msg -bar3

  # Download SlowDNS binary if missing
  if [[ ! -e ${ADM_inst}/dns-server ]]; then
    msg -ama " Descargando binario...."
    # Check architecture (ARM vs x86_64)
    [[ $(uname -m 2> /dev/null) != x86_64 ]] && {
      if wget --no-check-certificate -t3 -T3 -O /etc/ADMcgh/bin/SlowDNS https://raw.githubusercontent.com/ChumoGH/ADMcgh/main/BINARIOS/aarch64/SlowDNS.bin &>/dev/null ; then
        chmod +x /etc/ADMcgh/bin/SlowDNS
        [[ -e ${ADM_inst}/dns-server ]] && rm -f ${ADM_inst}/dns-server
        ln -s /etc/ADMcgh/bin/SlowDNS ${ADM_inst}/dns-server
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
      if wget --no-check-certificate -t3 -T3 -O /etc/ADMcgh/bin/SlowDNS https://raw.githubusercontent.com/ChumoGH/ADMcgh/main/BINARIOS/x86_64/SlowDNS.bin &>/dev/null ; then
        chmod +x /etc/ADMcgh/bin/SlowDNS
        [[ -e ${ADM_inst}/dns-server ]] && rm -f ${ADM_inst}/dns-server
        ln -s /etc/ADMcgh/bin/SlowDNS ${ADM_inst}/dns-server
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
    msg -bar3
  fi

  # Key configuration flow
  [[ -e ${ADM_slow}/pidfile ]] && {
    [[ -e "${ADM_slow}/server.pub" ]] && pub=$(cat ${ADM_slow}/server.pub)
    if [[ ! -z "$pub" ]]; then
      echo -ne "$(msg -ama " Usar clave existente [S/N]: ")"
      read ex_key
      case $ex_key in
        s|S|y|Y) tput cuu1 && tput dl1
        echo -e " $(msg -ama "KEY.PUB:") $(msg -verd "$(cat ${ADM_slow}/server.pub)")";;
        n|N) tput cuu1 && tput dl1
        rm -rf ${ADM_slow}/server.key
        rm -rf ${ADM_slow}/server.pub
        ${ADM_inst}/dns-server -gen-key -privkey-file ${ADM_slow}/server.key -pubkey-file ${ADM_slow}/server.pub &>/dev/null
        echo -e " $(msg -ama "KEY.PUB:") $(msg -verd "$(cat ${ADM_slow}/server.pub)")";;
        *);;
      esac
    else
      rm -rf ${ADM_slow}/server.key
      rm -rf ${ADM_slow}/server.pub
      ${ADM_inst}/dns-server -gen-key -privkey-file ${ADM_slow}/server.key -pubkey-file ${ADM_slow}/server.pub &>/dev/null
      echo -e " $(msg -ama "KEY.PUB:") $(msg -verd "$(cat ${ADM_slow}/server.pub)")"
    fi
  } || show_menu
  msg -bar3

  # Apply iptables rules
  if ! rule_exists filter "$rule1"; then
    iptables $rule1
    print_center -verd " REGLA DE TRAFICO AGREGADA "
  else
    print_center -verm2 " REGLA DE TRAFICO YA EXISTE "
  fi
  msg -bar3

  if ! rule_exists nat "$rule2"; then
    iptables $rule2
    print_center -verd " REGLA DE REDIRECCIONES AGREGADA "
  else
    print_center -verm2 " REGLA DE REDIRECCION YA EXISTE "
  fi
  msg -bar3

  print_center -verd "  INICIANDO SLOWDNS "
  systemctl restart networking.service &>/dev/null
  systemctl restart network-online.service &>/dev/null

  # Start the server in a screen session
  if screen -dmS slowdns ${ADM_inst}/dns-server -udp :5300 -privkey-file ${ADM_slow}/server.key $NS 127.0.0.1:$PORT ; then
    #-------------------------
    # Auto-boot Persistence: Add to /bin/autoboot
    [[ $(grep -wc "slowdns" /bin/autoboot) = '0' ]] && {
      echo -e "netstat -au | grep -w 5300 > /dev/null || {  screen -r -S 'slowdns' -X quit;  screen -dmS slowdns ${ADM_inst}/dns-server -udp :5300 -privkey-file ${ADM_slow}/server.key $NS 127.0.0.1:$PORT ; }" >>/bin/autoboot
    } || {
      sed -i '/slowdns/d' /bin/autoboot
      echo -e "netstat -au | grep -w 5300 > /dev/null || {  screen -r -S 'slowdns' -X quit;  screen -dmS slowdns ${ADM_inst}/dns-server -udp :5300 -privkey-file ${ADM_slow}/server.key $NS 127.0.0.1:$PORT ; }" >>/bin/autoboot
    }
    #crontab -l > /root/cron
    #echo "@reboot /bin/autoboot" >> /root/cron
    #crontab /root/cron
    service cron restart
    #-------------------------
    msg -verd "    Con Exito!!!"
    msg -bar3
  else
    msg -verm "    Con Fallo!!!"
    msg -bar3
  fi
  read -p "ENTER PARA CONTINUAR"
}


# Function: ini_slow_new
# Secondary Installation Logic (Dual Port)
# Sets up a second instance of SlowDNS on port 5400.
ini_slow_new(){
  msg -bra "INSTALADOR SLOWDNS SECUNDARIO "
  drop_port
  n=1
  for i in $DPB; do
    proto=$(echo $i|awk -F ":" '{print $1}')
    proto2=$(printf '%-12s' "$proto")
    port=$(echo $i|awk -F ":" '{print $2}')
    echo -e " $(msg -verd "[$n]") $(msg -verm2 ">") $(msg -ama " $(echo -e " ${flech} $proto2 "| tr [:lower:] [:upper:])")$(msg -azu "$port")"
    drop[$n]=$port
    dPROT[$n]=$proto2
    num_opc="$n"
    let n++
  done
  msg -bar3
  opc=$(selection_fun $num_opc)
  echo "${drop[$opc]}" > ${ADM_slow}/puertoSEC
  echo "${dPROT[$opc]}" > ${ADM_slow}/protcSEC
  local PORT=$(cat ${ADM_slow}/puertoSEC)
  local PRT=$(cat ${ADM_slow}/protcSEC)
  msg -bra " INSTALADOR SLOWDNS "
  msg -bar3
  echo -e " $(msg -ama "Redireccion SlowDns:") $(msg -verd "$(echo -e "${PRT}" | tr [:lower:] [:upper:])") : $(msg -verd "$PORT") $(msg -ama " -> ") $(msg -verd "5300")"
  msg -bar3
  [[ -e /dominio_NS.txt && ! -e ${ADM_slow}/domain_ns ]] && cp /dominio_NS.txt ${ADM_slow}/domain_ns
  [[ -e ${ADM_slow}/domain_ns ]] && NS1=$(cat < ${ADM_slow}/domain_ns) || unset NS1 NS
  unset NS
  [[ -z $NS1 ]] && {
    while [[ -z $NS ]]; do
      echo -ne "\e[1;31m TU DOMINIO NS \e[1;37m: "
      read NS
      tput cuu1 && tput dl1
    done
  } || {
    echo -e "\e[1;31m      TIENES UN DOMINIO NS YA REGISTRADO \e[1;37m "
    echo -e "\e[1;32m   TU NS ES : ${NS1} \e[1;37m "
    echo -e "  SI QUIERES UTILIZARLO, SOLO PRESIONA ENTER "
    echo -e "       CASO CONTRARIO DIJITA TU NUEVO NS "
    msg -bar3
    echo -ne "\e[1;31m TU DOMINIO NS \e[1;37m: "
    read NS
    [[ -z $NS ]] && NS="${NS1}"
    tput cuu1 && tput dl1
    echo "$NS" > ${ADM_slow}/domain_ns
  }
  echo "$NS" > ${ADM_slow}/domain_ns
  echo -e " $(msg -ama "NAME SERVER:") $(msg -verd "$NS")"
  msg -bar3
  if [[ ! -e ${ADM_inst}/dns-server ]]; then
    msg -ama " Descargando binario...."
    [[ $(uname -m 2> /dev/null) != x86_64 ]] && {
      if wget --no-check-certificate -t3 -T3 -O /etc/ADMcgh/bin/SlowDNS https://raw.githubusercontent.com/ChumoGH/ADMcgh/main/BINARIOS/aarch64/SlowDNS.bin &>/dev/null ; then
        chmod +x /etc/ADMcgh/bin/SlowDNS
        [[ -e ${ADM_inst}/dns-server ]] && rm -f ${ADM_inst}/dns-server
        ln -s /etc/ADMcgh/bin/SlowDNS ${ADM_inst}/dns-server
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
      if wget --no-check-certificate -t3 -T3 -O /etc/ADMcgh/bin/SlowDNS https://raw.githubusercontent.com/ChumoGH/ADMcgh/main/BINARIOS/x86_64/SlowDNS.bin &>/dev/null ; then
        chmod +x /etc/ADMcgh/bin/SlowDNS
        [[ -e ${ADM_inst}/dns-server ]] && rm -f ${ADM_inst}/dns-server
        ln -s /etc/ADMcgh/bin/SlowDNS ${ADM_inst}/dns-server
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
    msg -bar3
  fi
  [[ -e "${ADM_slow}/server.pub" ]] && pub=$(cat ${ADM_slow}/server.pub)
  if [[ ! -z "$pub" ]]; then
    echo -ne "$(msg -ama " Usar clave existente [S/N]: ")"
    read ex_key
    case $ex_key in
      s|S|y|Y) tput cuu1 && tput dl1
      echo -e " $(msg -ama "KEY.PUB:") $(msg -verd "$(cat ${ADM_slow}/server.pub)")";;
      n|N) tput cuu1 && tput dl1
      rm -rf ${ADM_slow}/server.key
      rm -rf ${ADM_slow}/server.pub
      ${ADM_inst}/dns-server -gen-key -privkey-file ${ADM_slow}/server.key -pubkey-file ${ADM_slow}/server.pub &>/dev/null
      echo -e " $(msg -ama "KE:") $(msg -verd "$(cat ${ADM_slow}/server.pub)")";;
      *);;
    esac
  else
    rm -rf ${ADM_slow}/server.key
    rm -rf ${ADM_slow}/server.pub
    ${ADM_inst}/dns-server -gen-key -privkey-file ${ADM_slow}/server.key -pubkey-file ${ADM_slow}/server.pub &>/dev/null
    echo -e " $(msg -ama "KEY.PUB:") $(msg -verd "$(cat ${ADM_slow}/server.pub)")"
  fi
  msg -bar3
  if ! rule_exists filter "$rule1SEC"; then
    iptables $rule1SEC
    print_center -verd " REGLA 2 DE TRAFICO AGREGADA "
  else
    print_center -verm2 " REGLA 2 DE TRAFICO YA EXISTE "
  fi
  msg -bar3
  if ! rule_exists nat "$rule2SEC"; then
    iptables $rule2SEC
    print_center -verd " REGLA 2 DE REDIRECCIONES AGREGADA "
  else
    print_center -verm2 " REGLA 2 DE REDIRECCION YA EXISTE "
  fi
  msg -bar3
  print_center -verd "  INICIANDO MULTI SLOWDNS "

  systemctl restart networking.service &>/dev/null
  systemctl restart network-online.service &>/dev/null

  if screen -dmS sl54 ${ADM_inst}/dns-server -udp :5400 -privkey-file ${ADM_slow}/server.key $NS 127.0.0.1:$PORT ; then
    #-------------------------
    # Auto-boot Persistence for Secondary Instance
    [[ $(grep -wc "sl54" /bin/autoboot) = '0' ]] && {
      echo -e "netstat -au | grep -w 5400 > /dev/null || {  screen -r -S 'sl54' -X quit;  screen -dmS sl54 ${ADM_inst}/dns-server -udp :5400 -privkey-file ${ADM_slow}/server.key $NS 127.0.0.1:$PORT ; }" >>/bin/autoboot
    } || {
      sed -i '/sl54/d' /bin/autoboot
      echo -e "netstat -au | grep -w 5400 > /dev/null || {  screen -r -S 'sl54' -X quit;  screen -dmS sl54 ${ADM_inst}/dns-server -udp :5400 -privkey-file ${ADM_slow}/server.key $NS 127.0.0.1:$PORT ; }" >>/bin/autoboot
    }
    #crontab -l > /root/cron
    #echo "@reboot /bin/autoboot" >> /root/cron
    #crontab /root/cron
    service cron restart
    #-------------------------
    msg -verd "    Con Exito!!!"
    msg -bar3
  else
    msg -verm "    Con Fallo!!!"
    msg -bar3
  fi
  msg -bar3
  print_center -verd "  ADVERTENCIA !!! \n ESTA FUNCION CONSISTE EN APLICAR UN \n Doble MultiConexion [ DUAL ] \n QUE PERMITIRA CONEXTAR OTRO SERVICIO !!\n "
  msg -bar3
  read -p "ENTER PARA CONTINUAR"
}


# Function: reset_slow
# Restarts the SlowDNS service and reapplies rules.
reset_slow(){
  clear
  msg -bar3
  msg -ama "        VERIFICANDO ESTADO SLOWDNS ...."
  msg -bar3
  if ! rule_exists filter "$rule1"; then
    iptables $rule1
    print_center -verd " REGLA DE TRAFICO AGREGADA "
  else
    print_center -verm2 " REGLA DE TRAFICO YA EXISTE "
  fi
  msg -bar3
  if ! rule_exists nat "$rule2"; then
    iptables $rule2
    print_center -verd " REGLA DE REDIRECCIONES AGREGADA "
  else
    print_center -verm2 " REGLA DE REDIRECCION YA EXISTE "
  fi
  msg -bar3
  # Kill existing slowdns screens
  screen -ls | grep slowdns | cut -d. -f1 | awk '{print $1}' | xargs kill
  NS=$(cat ${ADM_slow}/domain_ns)
  PORT=$(cat ${ADM_slow}/puerto)
  print_center -verd "  REINICIANDO SLOWDNS "
  systemctl restart networking.service &>/dev/null
  systemctl restart network-online.service &>/dev/null
  if screen -dmS slowdns ${ADM_inst}/dns-server -udp :5300 -privkey-file /root/server.key $NS 127.0.0.1:$PORT ;then
    msg -verd "        Con exito!!!"
    msg -bar3
  else
    msg -verm "        Con fallo!!!"
    msg -bar3
  fi
  read -p "ENTER PARA CONTINUAR"
}

# Function: stop_slow
# Stops the SlowDNS service and cleans up persistence.
stop_slow(){
  clear
  msg -bar3
  msg -ama "        Deteniendo SlowDNS...."
  systemctl restart networking.service &>/dev/null
  systemctl restart network-online.service &>/dev/null
  if screen -ls | grep slowdns | cut -d. -f1 | awk '{print $1}' | xargs kill ; then
    for pidslow in $(screen -ls | grep ".slowdns" | awk {'print $1'}); do
      screen -r -S "$pidslow" -X quit
    done
    [[ $(grep -wc "slowdns" /bin/autoboot) != '0' ]] && {
      sed -i '/slowdns/d' /bin/autoboot
    }
    screen -wipe >/dev/null
    msg -verd "         Con exito!!!"   msg -bar3
  else
    msg -verm "        Con fallo!!!"    msg -bar3
  fi
  read -p "ENTER PARA CONTINUAR"
}

# Function: optim_slow
# Optimization/Watchdog function.
# Installs a binary `rDNS.bin` which periodically restarts the service to ensure stability.
optim_slow(){
  local _time
  clear&&clear
  msg -bar3
  print_center -verd "  ADVERTENCIA !!! \n ESTA FUNCION CONSISTE EN APLICAR UN \n POTENCIADOR [ SCRIPT ] AUTOMATIZADOR \n QUE RESTABLESCA EL SERVICIO CADA CIERTO TIEMPO \n RECUERDA QUE NO ES 100% SEGURO MANTENER ESTABILIDAD \n EN LOS METODOS UDP "
  msg -bar3
  read -p "ENTER PARA CONTINUAR"
  [[ $(ps aux | grep 'rDNS.bin' | grep -v grep) ]] && {
    msg -bar3
    msg -ama " DETENIENDO SERVICIO DE VERIFICACION . . . "
    killall rDNS.bin &>/dev/null && msg -verd "[OK]" || msg -verm "[fail]"
    kill -9 $(ps x |  grep 'rDNS.bin'  | grep -v grep | awk '{print $1}') &>/dev/null
    msg -bar3
  } || {
    msg -ama " Descargando binario de AutoControl...."
    [[ $(uname -m 2> /dev/null) != x86_64 ]] && {
      if wget --no-check-certificate -t3 -T3 -O /etc/ADMcgh/bin/rDNS.bin https://raw.githubusercontent.com/ChumoGH/ADMcgh/main/BINARIOS/aarch64/rDNS.bin &>/dev/null ; then
        chmod +x /etc/ADMcgh/bin/rDNS.bin
        [[ -e /bin/rDNS.bin ]] && rm -f /bin/rDNS.bin
        ln -s /etc/ADMcgh/bin/rDNS.bin /bin/rDNS.bin
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
      if wget --no-check-certificate -t3 -T3 -O /etc/ADMcgh/bin/rDNS.bin https://raw.githubusercontent.com/ChumoGH/ADMcgh/main/BINARIOS/x86_64/rDNS.bin &>/dev/null ; then
        chmod +x /etc/ADMcgh/bin/rDNS.bin
        [[ -e /bin/rDNS.bin ]] && rm -f /bin/rDNS.bin
        ln -s /etc/ADMcgh/bin/rDNS.bin /bin/rDNS.bin
        msg -verd "[OK]"
      else
        msg -verm "[fail]"
        msg -bar3
        msg -ama "No se pudo descargar el binario"
        read -p "ENTER PARA CONTINUAR"
        exit 0
      fi
    }
    msg -bar3
    print_center -verd "  POR FAVOR, INGRESA EL INTERVALO DE REINICIOS  \n LOS SERVICIOS SE AUTOVALIDARAN"
    msg -bar3
    while [[ -z $_time ]]; do
      echo -ne "\e[1;31m VALIDACION EN HORAS  \e[1;37m: "
      read _time
      tput cuu1 && tput dl1
    done
    print_center -verd "  INICIANDO VALIDACION DE BINARIO "
    if screen -dmS ardns /bin/rDNS.bin ${_time}  ; then
      msg -verd "[OK]"
    else
      msg -verm "[fail]"
      msg -bar3
    fi
    msg -bar3
  }
  print_center -verm2 "  Funcion en Prediseño \n\n Power By @ChumoGH \n\n"
  msg bar3
  read -p "ENTER PARA CONTINUAR"
}

# Function: remove_slow
# Completely removes the SlowDNS installation, rules, and files.
remove_slow(){
  stop_slow
  rm -rf /ADMcgh/slow/*
  rm -rf /etc/adm-lite/slow
  delete_rule filter "$rule1"
  delete_rule filter "$rule1SEC"
  delete_rule nat "$rule2"
  delete_rule nat "$rule2SEC"
}

# ------------------------------------------------------------------------------
# Main Execution Loop
# ------------------------------------------------------------------------------
while true; do
  sudo resolvectl flush-caches &>/dev/null
  [[ -e ${ADM_slow}/protc ]] &&  PRT=$(cat ${ADM_slow}/protc | tr [:lower:] [:upper:]) ||  PRT='NULL'
  [[ -e ${ADM_slow}/puerto ]] &&  PT=$(cat ${ADM_slow}/puerto) ||  PT='NULL'
  [[ $(ps x | grep dns-server | grep -v grep) ]] &&  MT=$(msg -verd "ACTIVO!!!" ) ||  MT=$(msg -verm "INACTIVO!!!")
  msg -bar3
  tittle
  msg -ama "         INSTALADOR SLOWDNS | @ChumoGH${p1t0}Plus"
  msg -bar3 #
  echo -e " SlowDNS +" "${PRT} ""->" "${PT}"  "| ESTADO -> ${MT}"
  msg -bar3
  [[ $(ps x | grep -w 'sl54' | grep -v grep) ]] && {
    print_center -verd "  MultiSlowDNS INICIALIZADO "
    [[ -e ${ADM_slow}/protcSEC ]] && print_center -verd " PROT : $(cat ${ADM_slow}/protcSEC) -> $(cat ${ADM_slow}/puertoSEC) <|> $(ps x |  grep -w '5400'  | grep -v grep | awk '{print $1}'| head -1) " || print_center -verd " PROCESO ENCONTRADO | VERIFICACION FALLIDA "
    msg -bar3
  }
  [[ $(ps aux | grep 'rDNS.bin' | grep -v grep) ]] && {
    print_center -verd "  INICIANDO VALIDACION DE BINARIO "
    print_center -verd "  $(ps x |  grep 'rDNS.bin'  | grep -v grep | awk '{print $1}' | head -1) "
    msg -bar3
  }
  menu_func "Instalar SlowDns" "$(msg -verd "Ver Informacion")" "$(msg -ama "Reiniciar SlowDns")" "$(msg -verm2 "Detener SlowDns")" "$(msg -verm2 "Remover SlowDns")" "$(msg -ama "Optimizador SlowDNS")" "DualPort SlowDns"
  msg -bar3
  echo -ne "$(msg -verd "  [0]") $(msg -verm2 "=>>") " && msg -bra "\033[1;41m Volver "
  msg -bar3

  # Note: The authorization check is currently commented out in the loop.
  # [[ ! -e /etc/chekKEY ]] && chekKEY &>/dev/null

  opcion=$(selection_fun 7)
  case $opcion in
    1)ini_slow;;
    2)info;;
    3)reset_slow;;
    4)stop_slow;;
    5)remove_slow;;
    6)optim_slow;;
    7)ini_slow_new;;
    0)rm -f $HOME/done && break;;
  esac
done
