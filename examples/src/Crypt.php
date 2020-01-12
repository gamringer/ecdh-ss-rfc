<?php

declare(strict_types=1);

namespace gamringer\rfc\example;

use Jose\Component\Encryption\Algorithm\KeyEncryption\Util\ConcatKDF;
use Base64Url\Base64Url;

class Crypt
{
	protected $base58;
	protected $payload;
	protected $sender;
	protected $recipient;
	protected $output;

	public function __construct($payload, Peer $sender, Peer $recipient)
	{
		$this->base58 = new \StephenHill\Base58();
		$this->payload = $payload;
		$this->sender = $sender;
		$this->recipient = $recipient;
	}

	public function encode()
	{
		if (isset($this->output)) {
			return $this->output;
		}

		$symkey = \sodium_crypto_aead_xchacha20poly1305_ietf_keygen();
		
		[$headers, $encryptedKey] = $this->encodeRecipient($symkey);

	    $headers["alg"] = "ECDH-SS+XC20PKW";
	    $headers["enc"] = "XC20P";

		$headersEncoded = Base64Url::encode(json_encode($headers));

		$nonce = random_bytes(\SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
		$symoutput = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($this->payload, $headersEncoded, $nonce, $symkey);
		$tag = substr($symoutput, -\SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES);
		$ciphertext = substr($symoutput, 0, -\SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES);


		$this->output = [
			'protected' => $headersEncoded,
			'encrypted_key' => $encryptedKey,
			'iv' => Base64Url::encode($nonce),
			'tag' => Base64Url::encode($tag),
			'ciphertext' => Base64Url::encode($ciphertext),
		];

		return $this->output;
	}

	private function encodeRecipient($symkey)
	{
		$Z = sodium_crypto_scalarmult($this->sender->getPrivateKey(), $this->recipient->getPublicKey());
		$apu = Base64Url::encode(random_bytes(64));
		$kek = $this->concatKDF($Z, $apu);
		$nonce = random_bytes(\SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
		$kekoutput = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($symkey, '', $nonce, $kek);
		$tag = substr($kekoutput, -\SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES);
		$ciphertext = substr($kekoutput, 0, -\SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES);
		return [
			[
				'apu' => $apu,
				'iv' => Base64Url::encode($nonce),
				'tag' => Base64Url::encode($tag),
				'kid' => $this->base58->encode($this->recipient->getPublicKey()),
				'spk' => (new ProtectedJWK(
					$this->sender->getPublicKey(),
					$this->recipient->getPublicKey()
				))->__toString(),
			],
			Base64Url::encode($ciphertext),
		];
	}

	private function concatKDF($Z, $apu)
	{
		return ConcatKDF::generate($Z, 'XC20P', 256, $apu);
	}

	public function __toString()
	{
		return implode('.', $this->encode());
	}
}
