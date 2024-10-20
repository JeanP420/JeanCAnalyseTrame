#include <stdio.h>
#include "common.h"
#include "ip.h"

// Analyser entete IP
void analyserIP(char *trame, IP *ip) 
{

  // Version et IHL
    ip->version = (trame[0] >> 4) & 0xF;
    ip->IHL = trame[0] & 0xF;

    // Type de service
    ip->typeOfService = trame[1];

    // Longueur totale (2 octets)
    ip->totalLength = (trame[2] << 8) | trame[3];

    // Identification (2 octets)
    ip->identification = (trame[4] << 8) | trame[5];

    // Flags et offset de fragment (3 bits pour flags et 13 bits pour fragment offset)
    ip->flags = (trame[6] >> 5) & 0x7;
    ip->fragmentOffset = ((trame[6] & 0x1F) << 8) | trame[7];

    // Durée de vie (TTL)
    ip->timeToLive = trame[8];

    // Protocole
    ip->protocol = trame[9];

    // Checksum d'en-tête (2 octets)
    ip->HeaderChecksum = (trame[10] << 8) | trame[11];

    // Adresse IP source (4 octets)
    ip->sourceIP = (trame[12] << 24) | (trame[13] << 16) | (trame[14] << 8) | trame[15];

    // Adresse IP destination (4 octets)
    ip->destinationIP = (trame[16] << 24) | (trame[17] << 16) | (trame[18] << 8) | trame[19];


}

// Afficher une adresse IP
void afficherIPAddress(unsigned int address)
{
    //masque & sur chaque octet à afficher pour l'afficher en unsigned int
    printf("Adresse IP : %d.%d.%d.%d\n",
        (address >> 24) & 0xFF,
        (address >> 16) & 0xFF,
        (address >> 8) & 0xFF,
        address >> 0 & 0xFF);

}

// Afficher entete IP
void afficherIP(IP ip)
{
    printf("IP:\n");
    printf("    version: %d\n", ip.version);
    printf("    IHL: %d\n", ip.IHL);
    printf("    typeOfService: %d\n", ip.typeOfService);
    printf("    totalLength: %d\n", ip.totalLength);
    printf("    identification: %d\n", ip.identification);
    printf("    flags: %d\n", ip.flags);
    printf("    fragmentOffset: %d\n", ip.fragmentOffset);
    printf("    timeToLive: %d\n", ip.timeToLive);
    printf("    protocol: %d\n", ip.protocol);
    printf("    HeaderChecksum: %d\n", ip.HeaderChecksum);
    printf("    sourceIP: ");
    afficherIPAddress(ip.sourceIP);
    printf("\n    destinationIP: ");
    afficherIPAddress(ip.destinationIP);
    printf("\n");
}
