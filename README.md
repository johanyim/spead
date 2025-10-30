# Spead: Structure Preserving Encryption and Decryption

A command line tool to encrypt JSON files, preserving their schema and types

## Installation

### Prequisites

[Install Rust](https://rust-lang.org/tools/install/):

```sh
curl --proto '=https' --tlsv1.2 https://sh.rustup.rs -sSf | sh
```


### Installation

With Cargo from crates.io :

```sh
cargo install spead
```

With Cargo from git:

```sh
cargo install --git https://github,com/johanyim/spead.git
```


Building from source:
```sh
# Clone the repository
git clone https://github.com/johanyim/spead.git
cd spead.git

cargo build --release


cargo install --path .
```


## Features

- **Encryption**: 

- **Schema Preservation**: Ensures the original JSON structure and data types remain intact after encryption.

- **Secure Key Derivation**: Utilizes Argon2 for robust, password-based cryptographic key derivation.

- **CLI Integration**: Designed for shell scripts, supporting stdin and stdout for input and output.

- **Granular Control**: Fine-grained behavioral configuration through command-line flags.

## Command-line options




## Example





Consider the file, `file.json`:

```json
{
    "_id": 10,
    "username": "jdoe",
    "display_name": "John Doe",
    "email": "jdoe@example.com",
    "bio": "Rust developer and open-source contributor.",
    "address": {
        "street": "123 Main Street",
        "city": "Sampleville",
        "state": "CA",
        "postal_code": "90001",
        "country": "USA"
    },
    "hobbies": [
        "Rust",
        "Swimming",
        "Terraria"
    ],
    "relationships": [
        {
            "_id": 12,
            "username": "jdoe",
            "relation": "wife"
        },
        {
            "_id": 4,
            "username": "jsmith",
            "relation": "friend"
        }
    ],
    "followers": 120,
    "following": 120,
    "verified": true
}
```

Encrypted with the password `SECRET_PASSWORD` using the command:

```sh
spead -p SECRET_PASSWORD file.json
```


```json
{
  "_id": 6844942821675,
  "username": "ꍔ眮얚",
  "display_name": "벭牆腓롁⍗絔قથ",
  "email": "瓁晀崓讅驴ࢫቦỖ흱ꁤ䁶홀飬磌迕",
  "bio": "춾撲㫄솓ඊ⯘繢词䴐唇Ʇ᥌檎읗쏮懣笘ቍ딲穄梷㣈룬輡跺ꉈꃿ솤噝ᆗ繐匍荞쬫e䉈＂꺓䅾",
  "address": {
    "street": "縁ꐎ䄽㚚鏚诃ᗙ▆啼⩯空薕睇ꊐ鵐",
    "city": "⍞蓭⠥䚷䟍䝀쨏঱த셗걉",
    "state": "읠",
    "postal_code": "嵜暜攓㓸搯",
    "country": "풵嵐褎"
  },
  "hobbies": [
    "뺊祅栐탑",
    "짌闣੿࿲鷗䊤ᔴ",
    "稔»㺯頯쬴巡ᣲṇ"
  ],
  "relationships": [
    {
      "_id": 2687991330582,
      "username": "ꓒ鯭鋄㸖",
      "relation": "̞⧗瑍％"
    },
    {
      "_id": 4908835464068,
      "username": "㸱ᢁ➺珊棔ᘝ",
      "relation": "䑱ত懽墚馂곯"
    }
  ],
  "followers": 8552593308590,
  "following": 7161085169679,
  "verified": true
}
```


## Roadmap






