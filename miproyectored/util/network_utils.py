import ipaddress
import socket
from typing import List, Optional, Tuple

# Try to import netifaces
try:
    import netifaces
    NETIFACES_AVAILABLE = True
except ImportError:
    NETIFACES_AVAILABLE = False
    print("Warning: netifaces library not found. Interface names may not be available.")

def detect_local_networks() -> List[Tuple[str, str]]:
    """
    Detecta las redes locales (formato CIDR, ej. "192.168.1.0/24") a las que la máquina está conectada.
    incluyendo el nombre de la interfaz asociada.
    Requiere la librería `netifaces` para obtener nombres de interfaz precisos.
    Si `netifaces` no está disponible, usa un método de fallback menos preciso.
    """
    networks: List[Tuple[str, str]] = []
    processed_networks = set() # Para evitar duplicados de red

    if NETIFACES_AVAILABLE:
        print("Using netifaces for network detection.")
        try:
            for iface_name in netifaces.interfaces():
                try:
                    # Get addresses for the interface
                    addresses = netifaces.ifaddresses(iface_name)

                    # Check for IPv4 addresses
                    if netifaces.AF_INET in addresses:
                        for link in addresses[netifaces.AF_INET]:
                            ip_address_str = link['addr']
                            netmask_str = link.get('netmask') # Use .get for safety

                            if ip_address_str and netmask_str:
                                try:
                                    # Combine IP and netmask to get the network
                                    # ipaddress.ip_network expects IP/Netmask or IP/Prefix
                                    network = ipaddress.ip_network(f"{ip_address_str}/{netmask_str}", strict=False)
                                    network_cidr = str(network)

                                    # Check if it's a loopback address
                                    if not ipaddress.ip_address(ip_address_str).is_loopback:
                                        # Add to list if not already processed
                                        if network_cidr not in processed_networks:
                                            networks.append((network_cidr, iface_name))
                                            processed_networks.add(network_cidr)
                                            print(f"Detected network: {network_cidr} on interface {iface_name}")
                                except ValueError as e:
                                    print(f"Could not determine network for IP {ip_address_str} with netmask {netmask_str} on {iface_name}: {e}")
                                    pass # Skip this address
                            else:
                                print(f"Skipping interface {iface_name}: Missing IP or Netmask in AF_INET addresses.")

                except Exception as e:
                    # Catch errors specific to processing an interface
                    print(f"Error processing interface {iface_name} with netifaces: {e}")
                    pass # Continue to the next interface

        except Exception as e:
            # Catch errors during the initial call to netifaces.interfaces()
            print(f"Error listing interfaces with netifaces: {e}")
            print("Falling back to socket-based detection.")
            # Fallback if netifaces fails entirely
            return _fallback_detect_local_networks()

    else:
        # Fallback if netifaces is not available
        print("netifaces not available. Using fallback socket-based network detection.")
        return _fallback_detect_local_networks()

    # Ensure loopback networks (like 127.0.0.0/8) are excluded
    networks = [(cidr, name) for cidr, name in networks if not ipaddress.ip_network(cidr).is_loopback]

    # Add a default fallback if no networks were detected
    if not networks:
        default_ip = "192.168.1.0/24"
        networks.append((default_ip, "Default/Fallback"))
        print(f"No local networks detected. Using default: {default_ip}")

    return networks

def _fallback_detect_local_networks() -> List[Tuple[str, str]]:
    """
    Fallback function using socket if netifaces is not available.
    Less accurate, assumes /24 mask and may not get interface names.
    Returns tuples (network_cidr, generic_interface_info).
    """
    networks: List[Tuple[str, str]] = []
    processed_networks = set()

    try:
        hostname = socket.gethostname()
        # Obtener todas las IPs asociadas con el hostname
        # Esto puede devolver múltiples IPs si hay varias interfaces
        addr_info = socket.getaddrinfo(hostname, None)
        
        for item in addr_info:
            family, _, _, _, sockaddr = item
            if family == socket.AF_INET: # Solo IPv4
                ip_address_str = sockaddr[0]
                # Use IP address as generic interface info in fallback
                interface_info = "Interfaz Local (Fallback)" # Texto más genérico
                try:
                    # Crear un objeto de interfaz de red para obtener la dirección de red
                    # Asumimos una máscara /24 por simplicidad, esto es una gran suposición.
                    # Para una detección precisa de la máscara, se necesitarían métodos más avanzados.
                    ip_interface = ipaddress.ip_interface(f"{ip_address_str}/24") 
                    network_cidr = str(ip_interface.network)
                    if not ip_interface.is_loopback and network_cidr not in processed_networks:
                        networks.append((network_cidr, interface_info))
                        processed_networks.add(network_cidr)
                        print(f"Fallback detected network: {network_cidr} via IP {ip_address_str}")
                except ValueError:
                    # Podría fallar si la IP es, por ejemplo, de loopback y no se maneja bien con /24
                    print(f"No se pudo determinar la red para la IP: {ip_address_str}")
                    pass
        
        # Fallback si no se detectaron redes (ej. solo se obtuvo 127.0.0.1)
        if not networks:
            try:
                # Intento alternativo conectándose a un host externo (no establece conexión real)
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80)) # DNS de Google
                local_ip = s.getsockname()[0]
                s.close() # Texto más genérico
                interface_info = "Interfaz de Red (Fallback)"
                if local_ip and not ipaddress.ip_address(local_ip).is_loopback:
                    ip_interface = ipaddress.ip_interface(f"{local_ip}/24")
                    network_cidr = str(ip_interface.network)
                    if network_cidr not in processed_networks:
                        networks.append((network_cidr, interface_info))
                        processed_networks.add(network_cidr)
                        print(f"Fallback detected network: {network_cidr} via external connection IP {local_ip}")
            except Exception as e:
                print(f"Error en fallback de detección de red: {e}")

    except socket.gaierror as e:
        print(f"Error al obtener información de la dirección del host: {e}")
    except Exception as e:
        print(f"Error general al detectar redes locales: {e}")
        
    # Add a default fallback if no networks were detected even by fallback methods
    if not networks:
        default_ip = "192.168.1.0/24"
        networks.append((default_ip, "Default/Fallback"))
        print(f"Fallback: No local networks detected. Using default: {default_ip}")

    return networks

def calculate_network_address(ip: str, prefix_length: int) -> Optional[str]:
    """
    Calcula la dirección de red base a partir de una dirección IP y la longitud de su prefijo.
    """
    try:
        # ipaddress.ip_network espera la IP en formato CIDR o IP/máscara
        # Usamos strict=False para permitir IPs de host
        network = ipaddress.ip_network(f"{ip}/{prefix_length}", strict=False)
        return str(network.network_address)
    except ValueError as e:
        print(f"Error al calcular la dirección de red para '{ip}/{prefix_length}': {e}")
        return None

def get_hostname(ip_address: str) -> str:
    """
    Intenta resolver el nombre de host para una dirección IP dada.
    """
    try:
        hostname, _, _ = socket.gethostbyaddr(ip_address)
        return hostname
    except socket.herror: # Host no encontrado
        return ip_address
    except socket.gaierror: # Error de resolución de nombre
        return ip_address
    except Exception: # Otros errores
        return ip_address

if __name__ == '__main__':
    print("Redes locales detectadas:")
    local_nets = detect_local_networks()
    if local_nets:
        for net, iface in local_nets:
            print(net)
    else:
        print("No se pudieron detectar redes locales automáticamente.")
        print("Considera especificar el objetivo manualmente, ej. '192.168.1.0/24'.")

    print("\nEjemplo de cálculo de dirección de red:")
    print(f"Para 192.168.1.100/24 -> {calculate_network_address('192.168.1.100', 24)}")
    print(f"Para 10.0.5.30/16 -> {calculate_network_address('10.0.5.30', 16)}")

    print("\nEjemplo de resolución de hostname:")
    print(f"Hostname para 8.8.8.8: {get_hostname('8.8.8.8')}")
    # La siguiente línea es para pruebas locales, puedes descomentarla si la necesitas para depurar
    # o eliminarla si ya no es necesaria.
    # print(f"Hostname para una IP local (puede variar): {get_hostname('192.168.1.1')}") # Descomentar para probar