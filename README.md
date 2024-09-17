# Analizador de Tráfico de Red en Tiempo Real

Script Go que captura y analiza el tráfico de red en tiempo real proporcionando estadísticas e información sobre los paquetes que pasan a través de interfaces de red.
Este script es útil para varios tipos de profesionales IT, como administradores de red, ingenieros de red, sysadmins, los diferentes profesionales dentro de la rama de ciberseguridad (security analyst, security engineers, pentesters, etc) profesionales de DevOps que necesiten monitorear el tráfico de red para entornos de desarrollo/producción, etc, o para cualquier profesional a fin que desee monitorear su trafico de red.
## Características

- Captura y análisis de paquetes en tiempo real.
- Clasificación de paquetes por protocolo (TCP, UDP, ICMP, etc.).
- Cálculo y visualización de estadísticas de tráfico.
- Identificación de las direcciones IP y puertos más activos.
- Detección y alerta sobre patrones de tráfico inusuales o potencialmente maliciosos.
- Actualiza y muestra estadísticas en la consola cada 5 segundos.

## Requisitos 

1. **Instalación de Go**:
   - Asegúrate de tener Go instalado en tu sistema. Puedes descargarlo desde [aquí](https://golang.org/dl/).

2. **Paquetes Necesarios**:
   - Instala los paquetes de Go necesarios:
     ```sh
     go get github.com/google/gopacket
     go get github.com/google/gopacket/layers
     go get github.com/google/gopacket/pcap
     ```

3. **Paquete de Desarrollo libpcap**:
   - Instala el paquete de desarrollo `libpcap`:
     - **En Sistemas Basados en Ubuntu/Debian**:
       ```sh
       sudo apt-get update
       sudo apt-get install -y libpcap-dev
       ```
     - **En Fedora/CentOS/RHEL**:
       ```sh
       sudo dnf install -y libpcap-devel
       ```
       o
       ```sh
       sudo yum install -y libpcap-devel
       ```
     - **En macOS**:
       ```sh
       brew install libpcap
       ```

## Instalación

1. **Clonar el Repositorio**:
   ```sh
   git clone https://github.com/elliotsecops/network-analyzer.git
   cd network-analyzer
   ```

2. **Inicializar un Módulo de Go**:
   ```sh
   go mod init network-analyzer
   ```

3. **Agregar Dependencias**:
   ```sh
   go get github.com/google/gopacket
   go get github.com/google/gopacket/layers
   go get github.com/google/gopacket/pcap
   ```

4. **Compilar el Script**:
   ```sh
   go build -o network-analyzer network-analyzer.go
   ```

## Uso

### Identificar la Interfaz de Red Correcta

Antes de ejecutar el script, necesitas identificar la interfaz de red correcta que está `UP` y tiene una señal de portadora. Ejecuta el comando `ip link show` para listar todas las interfaces de red disponibles:

```sh
ip link show
```

Ejemplo del output:
```plaintext
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
2: enp2s0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc pfifo_fast state DOWN mode DEFAULT group default qlen 1000
    link/ether ec:a8:6b:4a:26:b5 brd ff:ff:ff:ff:ff:ff
3: wlp1s0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DORMANT group default qlen 1000
    link/ether 24:0a:64:8b:56:fd brd ff:ff:ff:ff:ff:ff
4: virbr0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN mode DEFAULT group default qlen 1000
    link/ether 52:54:00:ab:2f:d4 brd ff:ff:ff:ff:ff:ff
5: docker0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN mode DEFAULT group default 
    link/ether 02:42:77:a1:2b:84 brd ff:ff:ff:ff:ff:ff
```

### Puntos Clave para Identificar Interfaces Activas

1. **Estado**:
   - Busca interfaces con el estado `UP`.
   - Ejemplo: `wlp1s0: <BROADCAST,MULTICAST,UP,LOWER_UP>`

2. **Flags**:
   - Busca interfaces con la flag `LOWER_UP`, que indica que el enlace está activo y tiene una señal de portadora.
   - Ejemplo: `wlp1s0: <BROADCAST,MULTICAST,UP,LOWER_UP>`

### Ejecutar el Script

1. **Ejecución Básica**:
   - Ejecuta el script con el nombre de la interfaz correcta (por ejemplo, `wlp1s0`) y una duración de 60 segundos:
     ```sh
     sudo ./network-analyzer -i wlp1s0 -t 60
     ```

2. **Modo Verboso**:
   - Para habilitar el registro detallado, agrega la flag `-v`:
     ```sh
     sudo ./network-analyzer -i wlp1s0 -t 60 -v
     ```

3. **Registro en Archivo**:
   - Para registrar la salida en un archivo, usa la flag `-o`:
     ```sh
     sudo ./network-analyzer -i wlp1s0 -t 60 -o log.txt
     ```

4. **Ejecución Indefinida**:
   - Para ejecutar el script indefinidamente, establece la duración en `0`:
     ```sh
     sudo ./network-analyzer -i wlp1s0 -t 0
     ```

## Ejemplo de Salida

```plaintext
Estadísticas Actuales:
Paquetes TCP: 30
Paquetes UDP: 1989
Paquetes ICMP: 0
Otros Paquetes: 40
Total de Bytes: 2185411

Top 5 IPs más Activas:
1. 172.217.131.234: 1667 paquetes
2. 192.168.1.111: 287 paquetes
3. 142.250.64.238: 22 paquetes
4. 192.168.1.1: 11 paquetes
5. 192.168.1.107: 10 paquetes

Top 5 Puertos más Activos:
1. Puerto 443: 1702 paquetes
2. Puerto 46115: 243 paquetes
3. Puerto 5353: 19 paquetes
4. Puerto 52170: 14 paquetes
5. Puerto 46449: 12 paquetes
```

## Solución de Problemas

1. **Permisos Insuficientes**:
   - Asegúrate de ejecutar el script con privilegios suficientes (por ejemplo, usando `sudo`).

2. **Interfaz No Encontrada**:
   - Verifica que la interfaz de red especificada exista y esté activa.

3. **Pérdida de Paquetes**:
   - Si experimentas pérdida de paquetes, considera aumentar el tamaño del búfer o optimizar el script para un mayor rendimiento.

---

# Real-Time Network Traffic Analyzer

This script made in Go captures and analyzes network traffic in real time providing statistics and information about packets passing through a specific network interface.
This script is useful for various types of IT professionals, such as network administrators, network engineers, sysadmins, the different professionals within the cybersecurity branch (security analyst, security engineers, pentesters, etc), DevOps professionals who need to monitor network traffic for development/production environments, etc, or for any professional who wants to monitor their network traffic.
## Features

- Real-time packet capture and analysis.
- Classification of packets by protocol (TCP, UDP, ICMP, etc.).
- Calculation and display of traffic statistics.
- Identification of the most active IP addresses and ports.
- Detection and alerting on unusual or potentially malicious traffic patterns.
- Updates and displays statistics on the console every 5 seconds.

## Prerequisites

1. **Go Installation**:
   - Ensure you have Go installed on your system. You can download it from [here](https://golang.org/dl/).

2. **Required Packages**:
   - Install the necessary Go packages:
     ```sh
     go get github.com/google/gopacket
     go get github.com/google/gopacket/layers
     go get github.com/google/gopacket/pcap
     ```

3. **libpcap Development Package**:
   - Install the `libpcap` development package:
     - **On Ubuntu/Debian-based Systems**:
       ```sh
       sudo apt-get update
       sudo apt-get install -y libpcap-dev
       ```
     - **On Fedora/CentOS/RHEL**:
       ```sh
       sudo dnf install -y libpcap-devel
       ```
       or
       ```sh
       sudo yum install -y libpcap-devel
       ```
     - **On macOS**:
       ```sh
       brew install libpcap
       ```

## Installation

1. **Clone the Repository**:
   ```sh
   git clone https://github.com/elliotsecops/network-analyzer.git
   cd network-analyzer
   ```

2. **Initialize a Go Module**:
   ```sh
   go mod init network-analyzer
   ```

3. **Add Dependencies**:
   ```sh
   go get github.com/google/gopacket
   go get github.com/google/gopacket/layers
   go get github.com/google/gopacket/pcap
   ```

4. **Compile the Script**:
   ```sh
   go build -o network-analyzer network-analyzer.go
   ```

## Usage

### Identifying the Correct Network Interface

Before running the script, you need to identify the correct network interface that is `UP` and has a carrier signal. Use the `ip link show` command to list all available network interfaces:

```sh
ip link show
```

Example output:
```plaintext
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
2: enp2s0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc pfifo_fast state DOWN mode DEFAULT group default qlen 1000
    link/ether ec:a8:6b:4a:26:b5 brd ff:ff:ff:ff:ff:ff
3: wlp1s0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DORMANT group default qlen 1000
    link/ether 24:0a:64:8b:56:fd brd ff:ff:ff:ff:ff:ff
4: virbr0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN mode DEFAULT group default qlen 1000
    link/ether 52:54:00:ab:2f:d4 brd ff:ff:ff:ff:ff:ff
5: docker0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN mode DEFAULT group default 
    link/ether 02:42:77:a1:2b:84 brd ff:ff:ff:ff:ff:ff
```

### Key Points to Identify Active Interfaces

1. **State**:
   - Look for interfaces with the state `UP`.
   - Example: `wlp1s0: <BROADCAST,MULTICAST,UP,LOWER_UP>`

2. **Flags**:
   - Look for interfaces with the `LOWER_UP` flag, which indicates that the link is up and has a carrier signal.
   - Example: `wlp1s0: <BROADCAST,MULTICAST,UP,LOWER_UP>`

### Running the Script

1. **Basic Execution**:
   - Run the script with the correct interface name (e.g., `wlp1s0`) and a duration of 60 seconds:
   
     ```sh
     sudo ./network-analyzer -i wlp1s0 -t 60
     ```

2. **Verbose Mode**:
   - To enable verbose logging, add the `-v` flag:
     
     ```sh
     sudo ./network-analyzer -i wlp1s0 -t 60 -v
     ```

3. **Logging to a File**:
   - To log the output to a file, use the `-o` flag:
     
     ```sh
     sudo ./network-analyzer -i wlp1s0 -t 60 -o log.txt
     ```

4. **Running Indefinitely**:
   - To run the script indefinitely, set the duration to `0`:
     
     ```sh
     sudo ./network-analyzer -i wlp1s0 -t 0
     ```

## Example Output

```plaintext
Current Statistics:
TCP Packets: 30
UDP Packets: 1989
ICMP Packets: 0
Other Packets: 40
Total Bytes: 2185411

Top 5 Active IPs:
1. 172.217.131.234: 1667 packets
2. 192.168.1.111: 287 packets
3. 142.250.64.238: 22 packets
4. 192.168.1.1: 11 packets
5. 192.168.1.107: 10 packets

Top 5 Active Ports:
1. Port 443: 1702 packets
2. Port 46115: 243 packets
3. Port 5353: 19 packets
4. Port 52170: 14 packets
5. Port 46449: 12 packets
```

## Troubleshooting

1. **Insufficient Permissions**:
   - Ensure you run the script with sufficient privileges (e.g., using `sudo`).

2. **Interface Not Found**:
   - Verify that the specified network interface exists and is up.

3. **Packet Loss**:
   - If you experience packet loss, consider increasing the buffer size or optimizing the script for higher throughput.

