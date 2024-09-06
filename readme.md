# Analysis of LoRaWAN 1.1 security stack

This repo several programs used to analyze the LoRaWAN 1.1 security, espacially the cryptography used in it.

### Reminder:
- AES-ECB is used as KDF is most cases to derive keys. In one case, it is used as encryption scheme for a block lower than 128 bits, so there is no security issue there.
- AES-CCM (CTR + CBC-MAC) is used to encrypt payload transmitted between end devices and the network.
- AES-CMAC is used to compute a MAC (called MIC in LoRaWAN litterature) to verify integrity and authenticity.
- AES is a reccomanded by NIST as a strong and verified encryption algorithm.
- ```MIC```: is the output of AES-CMAC to verify packet integrity.
- ```:FRMPayload```: is the encrypted payload with CCM.

The goal of the programs you can find in this repo is to verify that there is no bias related to AES implementation. As IoT is runned by small electronic devices some cryptographic issues can appear in some cases such as IV computation (bad randomness, bad entropy).

## Programs

1. **test_quality_bit**: coded in Rust to beneficiate of it execution performance, this program is used to compute different tests such as: 
    1. **Binomial test** on collected payload/MIC (AES-CCM/CMAC output)
        - $H_0$: The proportion of odd bits is 0.5 (the bits are evenly distributed between even and odd).
        - $H_A$: The proportion of odd bits is not 0.5.
        - $p = 0.000001$: as AES is considered as safe and secure.
        As the MIC has a 32 bits length, the test must try all $2^{32}$ possible masks. This will be tested on ```MIC``` and ```FRMPayload```.
        The test run as follow :
        $$
        \begin{align*}
        &\textbf{c}, \text{ a set of } n \text{ 32-bit FRMPayload/MIC} \\
        &\text{For each } f \in \{0, \ldots, 2^{32} - 1\} : \\
        &\quad A \gets \textbf{c} \land f \\
        &\quad \text{Collect the number of odd 1-bits in } A. \\
        &\quad \text{Check if the collected number does not reject } H_0. \text{ If so, it is added to the list rejecting } H_0.
        \end{align*}
        $$
        
        > This program is coded to be executed in parallel. With 8 core it takes about 3h to be executed on every  $30000$ ```MIC```/```FRMPayload``` with $2^{32} f$.

    2. **Odd test**: same as the Binomial test but instead of keeping only number that rejects $H_0$, they all are collected to compute a distribution.
    3. In ```analysis/```, you will find a jupyter notebook used to create graph based on test computed collected data such as AES bit distriubtions.
    4. **Mitmproxy**: used as proxy between a LoRaWAN gateway and the service provider to make a MITM attack to be able to access the HTTPS encrypted content. The goal is to collect data massively to be able to execute a good statistic test. 
    In the mitmproxy middleware, there are 2 categories:
        1. The middleware that collected the data that are transmitted by the gateway to the cloud (uplink and downlink).
        2. A serie of test to verify that the packet integrity work as explained in their LoRaWAN 1.1 specification.
    5. **cups_api_resp_parser**: used to parse the binary response of the server in CUPS protocol and be able to forge to try RCE on gateway.
    This program allows you to parse/build a response as your own.
    6. Deamon export and telegram bot were used in collect case to be able to commit automatically the collected data every hour in this repo. The telegram bot were used to be able to access these data anywhere at anytime

## Collected data

All data collected were use as security analysis purpose and available in this [repo](https://github.com/CSharper63/tb_iscs_lorawan_data_collection).

## Information

This work was carried out as part of a bachelor's thesis in cybersecurity at [HEIG-VD](https://heig-vd.ch) on the analysis of the security layer of the LoRaWAN 1.1 IoT protocol.

It has been supervised by Dr. Maxime Augier.

The whole analysis paper is available [there]() in french.

