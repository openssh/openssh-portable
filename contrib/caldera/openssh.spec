%define askpass		1.2.0

Name        	: openssh
Version     	: 2.9p1
Release     	: 1
Group       	: System/Network

Summary     	: OpenSSH free Secure Shell (SSH) implementation.
Summary(de) 	: OpenSSH - freie Implementation der Secure Shell (SSH).
Summary(es) 	: OpenSSH implementación libre de Secure Shell (SSH).
Summary(fr) 	: Implémentation libre du shell sécurisé OpenSSH (SSH).
Summary(it) 	: Implementazione gratuita OpenSSH della Secure Shell.
Summary(pt) 	: Implementação livre OpenSSH do protocolo 'Secure Shell' (SSH).

Copyright   	: BSD
Packager    	: Stephan Seyboth <sps@caldera.de>
#Icon        	: .
URL         	: http://www.openssh.com/

Obsoletes   	: ssh, ssh-clients, openssh-clients

BuildRoot   	: /tmp/%{Name}-%{Version}

Source0: ftp://ftp.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-%{Version}.tar.gz
Source1: http://www.ntrnet.net/~jmknoble/software/x11-ssh-askpass/x11-ssh-askpass-%{askpass}.tar.gz


%Package server
Group       	: System/Network
Requires    	: openssh = %{Version}
Obsoletes   	: ssh-server

Summary     	: OpenSSH Secure Shell protocol server (sshd).
Summary(de) 	: OpenSSH Secure Shell Protocol Server (sshd).
Summary(es) 	: Servidor del protocolo OpenSSH Secure Shell (sshd).
Summary(fr) 	: Serveur de protocole du shell sécurisé OpenSSH (sshd).
Summary(it) 	: Server OpenSSH per il protocollo Secure Shell (sshd).
Summary(pt) 	: Servidor do protocolo 'Secure Shell' OpenSSH (sshd).


%Package askpass
Group       	: System/Network
Requires    	: openssh = %{Version}
Obsoletes   	: ssh-extras

Summary     	: OpenSSH X11 pass-phrase dialog.
Summary(de) 	: OpenSSH X11 Passwort-Dialog.
Summary(es) 	: Aplicación de petición de frase clave OpenSSH X11.
Summary(fr) 	: Dialogue pass-phrase X11 d'OpenSSH.
Summary(it) 	: Finestra di dialogo X11 per la frase segreta di OpenSSH.
Summary(pt) 	: Diálogo de pedido de senha para X11 do OpenSSH.


%Description
OpenSSH (Secure Shell) provides access to a remote system. It replaces
telnet, rlogin,  rexec, and rsh, and provides secure encrypted 
communications between two untrusted hosts over an insecure network.  
X11 connections and arbitrary TCP/IP ports can also be forwarded over 
the secure channel.

%Description -l de
OpenSSH (Secure Shell) stellt den Zugang zu anderen Rechnern her. Es ersetzt
telnet, rlogin, rexec und rsh und stellt eine sichere, verschlüsselte
Verbindung zwischen zwei nicht vertrauenswürdigen Hosts über eine unsicheres
Netzwerk her. X11 Verbindungen und beliebige andere TCP/IP Ports können ebenso
über den sicheren Channel weitergeleitet werden.

%Description -l es
OpenSSH (Secure Shell) proporciona acceso a sistemas remotos. Reemplaza a
telnet, rlogin, rexec, y rsh, y proporciona comunicaciones seguras encriptadas
entre dos equipos entre los que no se ha establecido confianza a través de una
red insegura. Las conexiones X11 y puertos TCP/IP arbitrarios también pueden
ser canalizadas sobre el canal seguro.

%Description -l fr
OpenSSH (Secure Shell) fournit un accès à un système distant. Il remplace
telnet, rlogin, rexec et rsh, tout en assurant des communications cryptées
securisées entre deux hôtes non fiabilisés sur un réseau non sécurisé. Des
connexions X11 et des ports TCP/IP arbitraires peuvent également être
transmis sur le canal sécurisé.

%Description -l it
OpenSSH (Secure Shell) fornisce l'accesso ad un sistema remoto.
Sostituisce telnet, rlogin, rexec, e rsh, e fornisce comunicazioni sicure
e crittate tra due host non fidati su una rete non sicura. Le connessioni
X11 ad una porta TCP/IP arbitraria possono essere inoltrate attraverso
un canale sicuro.

%Description -l pt
OpenSSH (Secure Shell) fornece acesso a um sistema remoto. Substitui o
telnet, rlogin, rexec, e o rsh e fornece comunicações seguras e cifradas
entre duas máquinas sem confiança mútua sobre uma rede insegura.
Ligações X11 e portos TCP/IP arbitrários também poder ser reenviados
pelos porto seguro.

%Description server
This package installs the sshd, the server portion of OpenSSH. 

%Description -l de server
Dieses Paket installiert den sshd, den Server-Teil der OpenSSH.

%Description -l es server
Este paquete instala sshd, la parte servidor de OpenSSH.

%Description -l fr server
Ce paquetage installe le 'sshd', partie serveur de OpenSSH.

%Description -l it server
Questo pacchetto installa sshd, il server di OpenSSH.

%Description -l pt server
Este pacote intala o sshd, o servidor do OpenSSH.

%Description askpass
This package contains an X11-based passphrase dialog.

%Description -l de askpass
Dieses Paket enthält einen X11-basierten Passwort Dialog.

%Description -l es askpass
Este paquete contiene una aplicación para petición de frases-contraseña basada
en X11.

%Description -l fr askpass
Ce paquetage contient un dialogue de passphrase basé sur X11.

%Description -l it askpass
Questo pacchetto contiene una finestra di X11 che chiede la frase segreta.

%Description -l pt askpass
Este pacote contém um diálogo de senha para o X11.

%Prep
%setup
%setup -D -T -a1


%Build
CFLAGS="$RPM_OPT_FLAGS" \
./configure \
            --prefix=/usr \
            --sysconfdir=/etc/ssh \
            --libexecdir=/usr/lib/ssh \
            --with-pam \
            --with-tcp-wrappers \
            --with-ipv4-default \

make

cd x11-ssh-askpass-%{askpass}
xmkmf -a
make


%Install
%{mkDESTDIR}

make DESTDIR="$DESTDIR" install

make -C x11-ssh-askpass-%{askpass} DESTDIR="$DESTDIR" \
                                   BINDIR="/usr/lib/ssh" install

%{fixManPages}

# install remaining docs
NV="$DESTDIR%{_defaultdocdir}/%{Name}-%{Version}"
mkdir -p $NV
cp -a CREDITS ChangeLog LICENCE OVERVIEW README* TODO $NV
mkdir -p $NV/x11-ssh-askpass-%{askpass}
cp -a x11-ssh-askpass-%{askpass}/{README,ChangeLog,SshAskpass*.ad} \
      $NV/x11-ssh-askpass-%{askpass}


# OpenLinux specific configuration
mkdir -p $DESTDIR/{etc/pam.d,%{SVIcdir},%{SVIdir}}

# enabling X11 forwarding on the server is convenient and okay,
# on the client side it's a potential security risk!
%{fixUP} -vg  $DESTDIR/etc/ssh/sshd_config 'X11Forwarding no' \
                                           'X11Forwarding yes'

install -m644 contrib/caldera/sshd.pam $DESTDIR/etc/pam.d/sshd
# FIXME: disabled, find out why this doesn't work with nis
%{fixUP} -vg  $DESTDIR/etc/pam.d/sshd '(.*pam_limits.*)' '#$1'

install -m 0755 contrib/caldera/sshd.init $DESTDIR%{SVIdir}/sshd
%{fixUP} -T $DESTDIR/%{SVIdir} -e 's:\@SVIdir\@:%{SVIdir}:'
%{fixUP} -T $DESTDIR/%{SVIdir} -e 's:\@sysconfdir\@:/etc/ssh:'

cat <<-EoD > $DESTDIR%{SVIcdir}/sshd
	IDENT=sshd
	DESCRIPTIVE="OpenSSH secure shell daemon"
	# This service will be marked as 'skipped' on boot if there
	# is no host key. Use ssh-host-keygen to generate one
	ONBOOT="yes"
	OPTIONS=""
EoD

SKG=$DESTDIR/usr/sbin/ssh-host-keygen
install -m 0755 contrib/caldera/ssh-host-keygen $SKG
%{fixUP} -T $SKG -e 's:\@sysconfdir\@:/etc/ssh:'
%{fixUP} -T $SKG -e 's:\@sshkeygen\@:/usr/bin/ssh-keygen:'


# generate file lists
%{mkLists} -c %{Name}
%{mkLists} -d %{Name} << 'EOF'
/etc/ssh				base
^/etc/					IGNORED
%{_defaultdocdir}/$			IGNORED
askpass					askpass
*					default
EOF
%{mkLists} -a -f %{Name} << 'EOF'
^/etc					*		prefix(%%config)
/usr/X11R6/lib/X11/app-defaults		IGNORED
[Aa]skpass				askpass
%{_defaultdocdir}/%{Name}-%{Version}/	base
ssh-keygen				base
sshd					server
sftp-server				server
.*					base
EOF


%Clean
%{rmDESTDIR}


%Post
# Generate host key when none is present to get up and running,
# both client and server require this for host-based auth!
# ssh-host-keygen checks for existing keys.
/usr/sbin/ssh-host-keygen
: # to protect the rpm database


%Post server
if [ -x %{LSBinit}-install ]; then
  %{LSBinit}-install sshd
else
  lisa --SysV-init install sshd S55 3:4:5 K45 0:1:2:6
fi

! %{SVIdir}/sshd status || %{SVIdir}/sshd restart
: # to protect the rpm database


%PreUn server
[ "$1" = 0 ] || exit 0

! %{SVIdir}/sshd status || %{SVIdir}/sshd stop
: # to protect the rpm database


%PostUn server
if [ -x %{LSBinit}-remove ]; then
  %{LSBinit}-remove sshd
else
  lisa --SysV-init remove sshd $1
fi
: # to protect the rpm database


%Files -f files-%{Name}-base
%defattr(-,root,root)


%Files server -f files-%{Name}-server
%defattr(-,root,root)


%Files askpass -f files-%{Name}-askpass
%defattr(-,root,root)


%ChangeLog
* Mon Jan 01 1998 ...
Template Version: 1.31

$Id: openssh.spec,v 1.15 2001/04/27 05:50:49 tim Exp $
