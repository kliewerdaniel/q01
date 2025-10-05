"""
QuantumSecureComms CLI Tool

Command-line interface for quantum-resilient cryptographic protocols.
"""

import click
import sys
import json
from typing import Optional

from .qrng.qrng import QuantumRNG, generate_random_bits
from .qkd.bb84 import simulate_bb84
from .pqc.kyber import kyber_keygen
from .pqc.dilithium import dilithium_keygen
from .pqc.sphincs import sphincs_keygen
from .hybrid.hybrid import HybridCrypto, encrypt_file, decrypt_file
import logging

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@click.group()
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
@click.pass_context
def cli(ctx, verbose):
    """QuantumSecureComms: Modular quantum-resilient cryptography CLI"""
    ctx.ensure_object(dict)
    ctx.obj['verbose'] = verbose

    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        click.echo("Verbose mode enabled")


@cli.command()
@click.option('--bits', default=256, help='Number of random bits to generate')
@click.option('--explain', is_flag=True, help='Show step-by-step explanations')
@click.pass_context
def qrng(ctx, bits, explain):
    """Generate quantum random number bits using Qiskit"""
    qrng = QuantumRNG()
    try:
        random_bits, entropy = qrng.generate_random_bits(bits, explain=explain)
        click.echo(f"Generated {bits} random bits:")
        click.echo(''.join(map(str, random_bits)))
        click.echo(f"Shannon entropy: {entropy:.4f}")

        if ctx.obj['verbose']:
            click.echo(f"Bits list: {random_bits}")
    except Exception as e:
        click.echo(f"Error generating QRNG: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option('--protocol', default='BB84', type=click.Choice(['BB84']), help='QKD protocol to use')
@click.option('--bits', default=1024, help='Number of quantum bits to exchange')
@click.option('--explain', is_flag=True, help='Show step-by-step protocol details')
@click.option('--output', help='Output file for key material (JSON)')
@click.pass_context
def qkd(ctx, protocol, bits, explain, output):
    """Simulate Quantum Key Distribution protocols"""
    if protocol == 'BB84':
        try:
            key, qber, eve_detected = simulate_bb84(bits, explain=explain)

            click.echo(f"BB84 Protocol completed:")
            click.echo(f"Key length: {len(key)} bits")
            click.echo(f"QBER: {qber:.4f}")
            click.echo(f"Eavesdropping detected: {eve_detected}")

            if ctx.obj['verbose']:
                click.echo(f"Shared key: {''.join(map(str, key[:64]))}...")

            if output:
                result = {
                    'protocol': protocol,
                    'key_bits': len(key),
                    'qber': qber,
                    'eve_detected': eve_detected,
                    'key_hex': hex(int(''.join(map(str, key)), 2))[2:]
                }
                with open(output, 'w') as f:
                    json.dump(result, f, indent=2)
                click.echo(f"Results saved to {output}")

        except Exception as e:
            click.echo(f"Error in QKD simulation: {e}", err=True)
            sys.exit(1)


@cli.command()
@click.option('--algorithm', default='Kyber1024',
              type=click.Choice(['Kyber512', 'Kyber768', 'Kyber1024', 'Dilithium2', 'Dilithium3', 'Dilithium5',
                                'SPHINCS+-SHA256-128f-robust']),
              help='PQC algorithm to use for key generation')
@click.option('--explain', is_flag=True, help='Show step-by-step keygen details')
@click.option('--output', help='Output file for key pair (JSON)')
@click.option('--private', help='Output private key to file')
@click.option('--public', help='Output public key to file')
@click.pass_context
def keygen(ctx, algorithm, explain, output, private, public):
    """Generate post-quantum cryptographic key pairs"""
    try:
        if algorithm.startswith('Kyber'):
            keypair = kyber_keygen(algorithm, explain=explain)
        elif algorithm.startswith('Dilithium'):
            keypair = dilithium_keygen(algorithm, explain=explain)
        elif algorithm.startswith('SPHINCS'):
            keypair = sphincs_keygen(algorithm, explain=explain)
        else:
            click.echo(f"Unsupported algorithm: {algorithm}", err=True)
            sys.exit(1)

        click.echo(f"Generated {algorithm} key pair")

        if ctx.obj['verbose']:
            click.echo(f"Public key length: {len(keypair['public'])} bytes")
            click.echo(f"Private key length: {len(keypair['private'])} bytes")

        if output:
            # Convert bytes to hex for JSON serialization
            result = {
                'algorithm': algorithm,
                'public_key': keypair['public'].hex(),
                'private_key': keypair['private'].hex()
            }
            with open(output, 'w') as f:
                json.dump(result, f, indent=2)
            click.echo(f"Key pair saved to {output}")

        if private:
            with open(private, 'wb') as f:
                f.write(keypair['private'])
            click.echo(f"Private key saved to {private}")

        if public:
            with open(public, 'wb') as f:
                f.write(keypair['public'])
            click.echo(f"Public key saved to {public}")

    except Exception as e:
        click.echo(f"Error generating keys: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument('input_file', type=click.Path(exists=True))
@click.option('--hybrid', is_flag=True, help='Use hybrid cryptography (QKD + PQC)')
@click.option('--explain', is_flag=True, help='Show encryption details')
@click.option('--qkd-key', help='QKD shared secret hex string')
@click.option('--kem-key', help='PQC KEM shared secret hex string')
@click.option('--output', help='Output encrypted file path')
@click.pass_context
def encrypt(ctx, input_file, hybrid, explain, qkd_key, kem_key, output):
    """Encrypt files using quantum-resilient methods"""
    try:
        if hybrid:
            # Initialize hybrid crypto
            qkd_secret = bytes.fromhex(qkd_key) if qkd_key else None
            kem_secret = bytes.fromhex(kem_key) if kem_key else None

            if ctx.obj['verbose']:
                click.echo("Initializing hybrid cryptography...")
                if qkd_secret:
                    click.echo(f"QKD secret length: {len(qkd_secret)} bytes")
                if kem_secret:
                    click.echo(f"KEM secret length: {len(kem_secret)} bytes")

            hybrid_crypto = HybridCrypto(qkd_secret, kem_secret)

            encrypted_path, nonce, salt = encrypt_file(input_file, hybrid_crypto, explain=explain)

            output_file = output or encrypted_path
            if output:
                import shutil
                shutil.move(encrypted_path, output_file)

            click.echo(f"File encrypted: {input_file} -> {output_file}")

        else:
            click.echo("Non-hybrid encryption not implemented yet", err=True)
            sys.exit(1)

    except Exception as e:
        click.echo(f"Error encrypting file: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument('input_file', type=click.Path(exists=True))
@click.option('--hybrid', is_flag=True, help='Use hybrid decryption')
@click.option('--explain', is_flag=True, help='Show decryption details')
@click.option('--qkd-key', help='QKD shared secret hex string')
@click.option('--kem-key', help='PQC KEM shared secret hex string')
@click.option('--output', help='Output decrypted file path')
@click.pass_context
def decrypt(ctx, input_file, hybrid, explain, qkd_key, kem_key, output):
    """Decrypt files using quantum-resilient methods"""
    try:
        if hybrid:
            qkd_secret = bytes.fromhex(qkd_key) if qkd_key else None
            kem_secret = bytes.fromhex(kem_key) if kem_key else None

            hybrid_crypto = HybridCrypto(qkd_secret, kem_secret)

            decrypted_path = decrypt_file(input_file, hybrid_crypto, explain=explain)

            output_file = output or decrypted_path
            if output:
                import shutil
                shutil.move(decrypted_path, output_file)

            click.echo(f"File decrypted: {input_file} -> {output_file}")

        else:
            click.echo("Non-hybrid decryption not implemented yet", err=True)
            sys.exit(1)

    except Exception as e:
        click.echo(f"Error decrypting file: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option('--name', required=True, help='Your name/identifier')
@click.option('--port', default=5000, help='Port to listen on')
@click.option('--host', default='localhost', help='Host to bind to')
@click.pass_context
def chat(ctx, name, port, host):
    """Start secure chat application (placeholder)"""
    click.echo(f"Starting secure chat as {name} on {host}:{port}")
    click.echo("Secure chat implementation coming soon...")
    # TODO: Implement secure chat


if __name__ == '__main__':
    cli()
