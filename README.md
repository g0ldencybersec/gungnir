# Gungnir
In Norse mythology, Gungnir is the spear of the god Odin. It is known for always hitting the target of the attacker regardless of the attacker's skill.
## Description

Gungnir is a command-line tool written in Go that continuously monitors certificate transparency (CT) logs for newly issued SSL/TLS certificates. Its primary purpose is to aid security researchers and penetration testers in discovering new domains and subdomains as soon as they are issued certificates, allowing for timely security testing.

The tool connects to multiple CT logs and actively watches for new certificate entries. Whenever a new certificate is detected, Gungnir extracts the domains and subdomains present in the certificate's subject alternative names (SANs) and Common Name (CN) and prints them to stdout in real-time.

By running Gungnir continuously, security professionals can stay ahead of the curve and rapidly identify potential attack surfaces as soon as new domains or subdomains become active on the web. This proactive approach enables early reconnaissance, vulnerability scanning, and prompt remediation of any identified issues.

# Key features:

- **Real-time Monitoring:** Actively monitors multiple CT logs for newly issued certificates.
- **Domain Extraction:** Extracts domains and subdomains from certificate subject alternative names and common name.
- **Continuous Output:** Prints discovered domains and subdomains to stdout as they are detected.
- **Customizable Filtering:** Allows filtering output based a text file of root domains.
- **Memory-Efficient Deduplication:** Uses Bloom filters to prevent duplicate domain output without consuming excessive memory, even when processing millions of domains.

Gungnir is designed to be a lightweight and efficient tool, making it suitable for running on various platforms, from local machines to cloud instances or containerized environments.

## Installation

```sh
go install github.com/g0ldencybersec/gungnir/cmd/gungnir@latest
```

## Usage
# Options
```sh
Usage of gungnir:
  -debug            Debug CT logs to see if you are keeping up
  -dedup            Enable domain deduplication using Bloom filter (default: true)
  -dedup-capacity   Bloom filter capacity (number of domains to track) (default: 10000000)
  -dedup-fpr        Bloom filter false positive rate (default: 0.001 = 0.1%%)
  -f                Monitor the root domain file for updates and restart the scan. requires the -r flag
  -j                JSONL output cert info
  -nc               NATs credentials file to publish domains to
  -ns               NATs subject to publish domains to
  -nu               NATs URL to publish domains to
  -o                Directory to store output files (one per hostname, requires -r flag)
  -r                Path to the list of root domains to filter against
  -v                Output go logs (500/429 errors) to command line
```

To run the tool, use a text file of root domains you want to monitor: `roots.txt`. Then, run the `gungnir` module:

```sh
gungnir -r roots.txt (filtered)
- or -
gungnir -r roots.txt -f (filtered and following)
- or -
gungnir (unfiltered)

```

Once the tool starts and initializes, it will print domains to stdout. So feel free to pipe the output into your favorite tool!

## Deduplication

Gungnir includes a memory-efficient deduplication feature that prevents duplicate domains from being output, even when processing millions of domains. This feature uses Bloom filters, a probabilistic data structure that provides constant memory usage regardless of the number of domains processed.

### How It Works

- **Bloom Filter Technology:** Uses probabilistic data structures that use fixed memory (typically 5-15MB) regardless of domain count
- **Zero False Negatives:** If a domain is marked as new, it's definitely new (no duplicates will slip through)
- **Configurable False Positive Rate:** Small chance (default 0.1%) that a duplicate might be allowed through, but this is an acceptable trade-off for memory efficiency
- **Per-File Deduplication:** When using file output mode (`-o`), each root domain file has its own deduplicator
- **Global Deduplication:** For stdout/NATS/Actor modes, a single global deduplicator tracks all domains

### Memory Usage

The deduplication feature uses constant memory based on your configuration:

| Capacity | False Positive Rate | Memory Usage |
|----------|---------------------|--------------|
| 1M       | 0.1%                | ~1.4MB       |
| 10M      | 0.1%                | ~14.4MB      |
| 100M     | 0.1%                | ~144MB       |
| 10M      | 1%                  | ~9.6MB       |

### Usage Examples

```sh
# Use default deduplication (enabled, 10M capacity, 0.1% FPR)
gungnir -r roots.txt

# Disable deduplication
gungnir -r roots.txt -dedup=false

# Custom capacity for high-volume processing
gungnir -r roots.txt -dedup-capacity=50000000

# Lower memory usage with slightly higher false positive rate
gungnir -r roots.txt -dedup-capacity=10000000 -dedup-fpr=0.01

# View deduplicator stats (use -v flag)
gungnir -r roots.txt -v
```

### When to Adjust Settings

- **High Volume (100K+ domains/hour):** Increase capacity to 50M-100M
- **Low Memory Systems:** Reduce capacity to 1M-5M or increase FPR to 1%
- **Maximum Precision:** Keep default settings (10M capacity, 0.1% FPR)
- **Disable Deduplication:** Use `-dedup=false` if you need exact duplicate tracking (not recommended for high-volume scenarios)

## Warranty

The creator(s) of this tool provides no warranty or assurance regarding its performance, dependability, or suitability for any specific purpose.

The tool is furnished on an "as is" basis without any form of warranty, whether express or implied, encompassing, but not limited to, implied warranties of merchantability, fitness for a particular purpose, or non-infringement.

The user assumes full responsibility for employing this tool and does so at their own peril. The creator(s) holds no accountability for any loss, damage, or expenses sustained by the user or any third party due to the utilization of this tool, whether in a direct or indirect manner.

Moreover, the creator(s) explicitly renounces any liability or responsibility for the accuracy, substance, or availability of information acquired through the use of this tool, as well as for any harm inflicted by viruses, malware, or other malicious components that may infiltrate the user's system as a result of employing this tool.

By utilizing this tool, the user acknowledges that they have perused and understood this warranty declaration and agree to undertake all risks linked to its utilization.

## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) for details.

## Contact

For assistance, use the Issues tab. If I do not respond within 7 days, please reach out to me here.

- [Gunnar Andrews](https://twitter.com/G0LDEN_infosec)
