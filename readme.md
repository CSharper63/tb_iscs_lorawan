# Analysis of LoRaWAN 1.1 security stack

This repo contains several programs used to analyze the LoRaWAN 1.1 security, especially the cryptography used in it.

## Information

This work was carried out as part of a bachelor's thesis in cybersecurity at [HEIG-VD](https://heig-vd.ch) on the analysis of the security layer of the LoRaWAN 1.1 IoT protocol.

It has been supervised by Dr. Maxime Augier.

> [!TIP]
> [The full analysis report is available here](https://maxime.chantemargue.ch/assets/lorawan_security/report.pdf). It explains steps of each analysis and how to reproduce them if you wish.

### Reminder
- AES-ECB is used as KDF in most cases to derive keys. In one case, it is used as an encryption scheme for a block lower than 128 bits, so there is no security issue there.
- AES-CCM (CTR + CBC-MAC) is used to encrypt payloads transmitted between end devices and the network.
- AES-CMAC is used to compute a MAC (called MIC in LoRaWAN literature) to verify integrity and authenticity.
- AES is recommended by NIST as a strong and verified encryption algorithm.
- ```MIC```: is the output of AES-CMAC to verify packet integrity.
- ```:FRMPayload```: is the encrypted payload with CCM.

The goal of the programs you can find in this repo is to verify that there is no bias related to AES implementation. As IoT is run by small electronic devices, some cryptographic issues can appear in some cases such as IV computation (bad randomness, bad entropy).
## Programs

1. [**test_quality_bit**](/analysis/test_bit_quality/src/main.rs): coded in Rust to benefit from its execution performance, this program is used to compute different tests such as: 
    1. [**Binomial test**](/analysis/test_bit_quality/src/main.rs) on collected payload/MIC (AES-CCM/CMAC output)
        - $H_0$: The proportion of odd bits is 0.5 (the bits are evenly distributed between even and odd).
        - $H_A$: The proportion of odd bits is not 0.5.
        - $p = 0.000001$: as AES is considered secured and strong. Threshold is $2^{32}*p=4294.967296$.
        As the MIC has a 32-bit length, the test must try all 232232 possible masks. This will be tested on ```MIC``` and ```FRMPayload```.
        The test run as follow :
        - $C$ is a set of $n$ ```MIC```/```FRMPayload```
        - For each $f$ ∈ {0, … , 232 − 1}
            - $A$ ⟵ $c$ ∧ $f$, $c$ is a element of $C$.
            - Collect the number of odd 1-bits in $A$
            - Check if the collected number does not reject $H_0$. If so, it is added to the list rejecting $H_0$ 

        > This program is coded to be executed in parallel. With 8 cores it takes about 3h to be executed on every  $30000$ ```MIC```/```FRMPayload``` with $2^{32} f$.

    2. [**Odd test**](/analysis/test_bit_quality/src/main.rs): same as the Binomial test but instead of keeping only numbers that reject $H_0$, they all are collected to compute a distribution.
    3. (**IV reuse detection**)[(/analysis/test_bit_quality/src/main.rs)]: part of test_quality_bit program. It is used to extract all stream cipher IV reuse. then another part of the program will combine all the messages by xor, with a repetition of IVs between them to try to discover patterns.   
    4. In [```analysis/```](/analysis/notebook.ipynb), you will find a jupyter notebook used to create graphs based on test computed collected data such as AES bit distributions.
2. [**Man-In-The-Middle proxy**](/mitmproxy/log_requests.py): used as a proxy ([mitmproxy](https://hub.docker.com/r/mitmproxy/mitmproxy/)) between a LoRaWAN gateway and the service provider to make a MITM attack to be able to access the HTTPS encrypted content. The goal is to collect data massively to be able to execute a good statistical test. 
In the mitmproxy middleware, there are 2 categories:
    1. The middleware that collected the data that are transmitted by the gateway to the cloud (uplink and downlink).
    2. A serie of test to verify that the packet integrity works as explained in their LoRaWAN 1.1 specification.
3. [**cups_api_resp_parser**](/cups_api_resp_parser/parser.py): used to parse the binary response of the server in CUPS protocol and be able to forge to try RCE on gateway.
This program allows you to parse/build a response as your own.
4. Deamon export and telegram bot was used in collect case to be able to commit automatically the collected data every hour in this repo. The telegram bot were used to be able to access these data anywhere at any time.

> [!TIP]
> All test executed from [```test_quality_bit```](/analysis/test_bit_quality/src/main.rs) program are based on real collected data in json format. You can find them in the next section.

## Collected data

All data collected were use as security analysis purpose and available in this [repo](https://github.com/CSharper63/tb_iscs_lorawan_data_collection).

# Conclusion

Overall, the combination of algorithms used to guarantee security seems to be working well. Based on the present analyses, there are no problems with the protocol.

> [!CAUTION]
> On the other hand, several devices seem to be reusing IV/Nonce in AES-CCM, which is totally catastrophic and compromises all security. From this point of view, it's worth remembering to be very careful when using stream ciphers like AES-CCM. **Never reuse an IV**.
